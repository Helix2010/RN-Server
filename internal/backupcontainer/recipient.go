package backupcontainer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// SlotCount 是恢复公钥的槽位数，写死 3。
//
// 门限就是 2-of-3：三个人，任意两个能开（设计 §2.1）。**没有降级模式**——少一把
// 不会悄悄退回两把跑，而是拒绝启用备份。理由是这套东西唯一的失败方式是「以为有、
// 其实没有」：一个能在两把钥匙下继续产出的实现，意味着某天有人删掉一把、控制台
// 照常绿、可用性已经掉回去了，没有任何人会发现。
//
// 也不支持四把以上：C(4,2)=6 个包，人的流程撑不住。
const SlotCount = 3

// SlotNames 是三个槽位的名字，顺序固定。它决定包名（<seq>-AB.rnbk），所以
// **一旦分配就不能重排**——重排会让「哪个包要谁的钥匙」在全部历史记录上错位。
var SlotNames = [SlotCount]string{"A", "B", "C"}

// Pair 是一组配对：外层封给 Outer，内层封给 Inner，包名是 Name。
type Pair struct {
	Name  string
	Inner string
	Outer string
}

// Pairs 按规则展开三组配对，而不是硬编码三个常量。
//
// 规则：取槽位集合，按字母序两两组合；对每一组 (X, Y)（X 在前），
// **内层封给 X，外层封给 Y，包名 XY**。
//
// 打包机要知道封几份内层、服务端要知道封几个外层，两边都从这里推，**不互相下发**
// ——下发就是又给了服务端一个指定收件人的口子，而「服务端不能指定收件人」是
// 「服务端读不到签名密钥」这条论证的地基（§4.2）。
func Pairs() []Pair {
	out := make([]Pair, 0, SlotCount*(SlotCount-1)/2)
	for i := 0; i < SlotCount; i++ {
		for j := i + 1; j < SlotCount; j++ {
			out = append(out, Pair{
				Name:  SlotNames[i] + SlotNames[j],
				Inner: SlotNames[i],
				Outer: SlotNames[j],
			})
		}
	}
	return out
}

// InnerSlots 是需要产出内层密文的槽位——三组配对里的内层收件人去重之后的结果。
//
// 结果是 {A, B} 两个，不是三个：AB 和 AC 共用封给 A 的那一份。打包机解密全部租户
// 签名密钥、打 tar 这件重活因此只做两遍而不是三遍。
func InnerSlots() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, p := range Pairs() {
		if !seen[p.Inner] {
			seen[p.Inner] = true
			out = append(out, p.Inner)
		}
	}
	return out
}

// ParsePublicKey 读一把恢复公钥：**PEM 的 base64，单行**。
//
// 为什么外面套一层 base64 而不是直接放 PEM：PEM 带换行，直接写进 systemd 的
// EnvironmentFile 极易写坏——而这个键要用的那一天，正好是最不该出意外的那一天。
//
// 服务端和打包机共用这一个解析器。两份实现迟早会在「允不允许尾随空白」「接不接受
// PKCS#1」这种地方漂开，而漂开的表现是两边算出不同的指纹、打包机拒绝执行，
// 排查起来毫无线索。
func ParsePublicKey(encoded string) (*rsa.PublicKey, error) {
	trimmed := strings.TrimSpace(encoded)
	if trimmed == "" {
		return nil, errors.New("value is empty")
	}
	der, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("value is not valid base64 (it must be the base64 of the PEM file, on one line): %w", err)
	}
	block, _ := pem.Decode(der)
	if block == nil {
		return nil, errors.New("the decoded value is not PEM; base64 the whole -----BEGIN PUBLIC KEY----- file")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a PKIX public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected an RSA public key, got %T", parsed)
	}
	if bits := pub.N.BitLen(); bits < minRecipientBits {
		return nil, fmt.Errorf("the key is %d bits; %d or more is required (4096 recommended)", bits, minRecipientBits)
	}
	return pub, nil
}
