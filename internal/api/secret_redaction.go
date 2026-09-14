package api

import (
	_ "embed"
	"regexp"
	"strings"
)

// 服务端入口的秘密扫描：诊断日志落盘前的第二遍脱敏（设计 diagnostic-report-2026-09-14 §3.5）。
//
// 规则与 RN-App src/core/security/secret-scan.ts **逐字节一致**，由两边共享的
// contracts/secret-redaction.v1.json 守着。第一遍在 App 出口已经做过；这里命中意味着
// 那一遍没拦住——旧版本或被改过的客户端——所以调用方要把命中数记下来，而不只是遮掉。
//
// 没有 canary：canary 是 App 预发构建里种的测试值，服务端无从知道。

// bip39English 是 BIP-39 英文词表（2048 词），由 RN-App 的 ethers LangEn 导出。
// 嵌入数据文件而不是引入一个 bip39 依赖：这里只需要"是不是表里的词"。
//
//go:embed bip39_english.txt
var bip39EnglishRaw string

var bip39English = func() map[string]struct{} {
	words := strings.Fields(bip39EnglishRaw)
	set := make(map[string]struct{}, len(words))
	for _, word := range words {
		set[word] = struct{}{}
	}
	return set
}()

const (
	redactedSecret   = "[redacted:secret]"
	minMnemonicWords = 12
)

var (
	letterRun  = regexp.MustCompile(`[A-Za-z]+`)
	pairingURI = regexp.MustCompile(`wc:[0-9a-fA-F]{8,}@\d+\?[^\s"']*symKey=[0-9a-fA-F]+`)
)

type textRange struct{ start, end int }

// mnemonicRanges 找出连续落在词表内、且至少 12 个词的片段。标点、数字、换行不打断连续段，
// 只有词表外的词才打断——与 App 侧相同，见契约向量里的对应用例。
func mnemonicRanges(text string) []textRange {
	var ranges []textRange
	runStart, runEnd, runLength := -1, -1, 0
	flush := func() {
		if runLength >= minMnemonicWords {
			ranges = append(ranges, textRange{runStart, runEnd})
		}
		runStart, runEnd, runLength = -1, -1, 0
	}
	for _, token := range letterRun.FindAllStringIndex(text, -1) {
		if _, ok := bip39English[strings.ToLower(text[token[0]:token[1]])]; ok {
			if runLength == 0 {
				runStart = token[0]
			}
			runLength++
			runEnd = token[1]
		} else {
			flush()
		}
	}
	flush()
	return ranges
}

// findSecretKinds 返回文本里有哪几类秘密（按字母序），与 App 侧 findSecrets 对齐。
func findSecretKinds(text string) []string {
	kinds := []string{}
	if len(mnemonicRanges(text)) > 0 {
		kinds = append(kinds, "mnemonic")
	}
	if pairingURI.MatchString(text) {
		kinds = append(kinds, "pairing-uri")
	}
	return kinds
}

// redactSecrets 把命中的部分换成 [redacted:secret]，其余原样保留；返回结果与是否命中。
// 顺序与 App 侧一致：先配对 URI，再在替换后的文本上找助记词。
func redactSecrets(text string) (string, bool) {
	result := pairingURI.ReplaceAllString(text, redactedSecret)
	hit := result != text
	ranges := mnemonicRanges(result)
	for i := len(ranges) - 1; i >= 0; i-- {
		result = result[:ranges[i].start] + redactedSecret + result[ranges[i].end:]
	}
	return result, hit || len(ranges) > 0
}
