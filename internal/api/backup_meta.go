package api

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Helix2010/RN-Server/internal/backupcontainer"
)

// 打包机随内层密文上报的元数据（设计 platform-backup-recovery-2026-09-15 §4.7）。
//
// 外层 manifest.json、RECOVERY.md 和 recover.sh 都由服务端生成，但它们有一半内容
// **只有打包机知道**——服务端打不开内层，拿不到租户清单、agent-key 指纹、内层每个
// 文件该放到哪。所以上报不是「一段密文」，是密文 + 签名 + 这份元数据三样。
//
// **服务端只转义和渲染，不解释。** innerFiles 里的路径会被渲染进 recover.sh，而那
// 个脚本恢复时以 root 跑——这条路径就是一个命令注入面。而且「服务端能让打包机执行
// 任意代码」那个洞修好之前，打包机本身也不完全可信，所以这里的每一项都当外部输入
// 校验。校验很便宜，正好把注入路径一起堵掉。
type backupPayloadMeta struct {
	// RecipientSlot 说明这一份内层封给了哪个槽位。一次备份要传两份（A 和 B），
	// 服务端靠它决定哪一份进哪个包
	RecipientSlot            string             `json:"recipientSlot"`
	AgentVersion             string             `json:"agentVersion"`
	AgentKeyFingerprint      string             `json:"agentKeyFingerprint"`
	BackupSigningFingerprint string             `json:"backupSigningFingerprint"`
	Tenants                  []backupMetaTenant `json:"tenants"`
	InnerFiles               []backupMetaFile   `json:"innerFiles"`
}

type backupMetaTenant struct {
	Slug         string `json:"slug"`
	Domain       string `json:"domain"`
	HasKeystore  bool   `json:"hasKeystore"`
	SignerSHA256 string `json:"signerSha256"`
}

// backupMetaFile 就是内层 manifest.json 的 files[] 一项，原样上来。
// 服务端拿 Target / Mode / Owner 渲染 RECOVERY.md 里「哪个文件放到哪」那一段，
// 以及 recover.sh 里对应的那几行
type backupMetaFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Target string `json:"target"`
	Mode   string `json:"mode"`
	Owner  string `json:"owner"`
}

const (
	// backupMetaMaxBytes 是 meta 部件的上限。它排在 payload 之前，所以服务端可以
	// 先解析元数据、校验通过再决定要不要收那 512 MiB
	backupMetaMaxBytes = 256 * 1024
	backupMaxTenants   = 500
	backupMaxInnerFile = 2000
)

var (
	backupSlugPattern = regexp.MustCompile(`^[a-z0-9-]+$`)
	backupModePattern = regexp.MustCompile(`^0[0-7]{3}$`)
	backupHexPattern  = regexp.MustCompile(`^[0-9a-f]+$`)
	// backupOwnerPattern 是 user:group。它同样进 recover.sh
	backupOwnerPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]*:[a-z_][a-z0-9_-]*$`)
)

// backupUnsafeInPath 是渲染进 shell 脚本时会被解释的字符。
//
// 单独列出来而不是用白名单，是因为路径里合法字符很多（点、斜杠、下划线、连字符、
// 数字、字母），而危险的就这些。任何一个出现都直接拒收——不是转义了事：一条
// 带 $(...) 的路径没有任何正当理由出现在备份包里，它只可能是攻击或者严重的 bug。
const backupUnsafeInPath = "$&|;<>()*?[]{}!#~" + // shell 元字符
	"\"'" + // 引号
	"`" + // 命令替换
	"\\" + // 反斜杠
	"\n\r\t" // 空白，会让一行命令断成两条

func parseBackupPayloadMeta(raw []byte) (backupPayloadMeta, error) {
	if len(raw) > backupMetaMaxBytes {
		return backupPayloadMeta{}, fmt.Errorf("meta is %d bytes, the limit is %d", len(raw), backupMetaMaxBytes)
	}
	var meta backupPayloadMeta
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&meta); err != nil {
		return backupPayloadMeta{}, fmt.Errorf("meta is not valid JSON: %w", err)
	}
	if err := meta.validate(); err != nil {
		return backupPayloadMeta{}, err
	}
	return meta, nil
}

func (m backupPayloadMeta) validate() error {
	if !isBackupSlotName(m.RecipientSlot) {
		return fmt.Errorf("recipientSlot %q is not one of %v", m.RecipientSlot, backupcontainer.SlotNames)
	}
	if err := checkBackupText("agentVersion", m.AgentVersion, 120, true); err != nil {
		return err
	}
	// agent-key 的指纹是 16 字符截断形式，备份签名公钥是 64 字符 DER SPKI——
	// 两种不同的定义，写在一起是为了让实现者不要再发明第三种（§2.2）
	if len(m.AgentKeyFingerprint) != 16 || !backupHexPattern.MatchString(m.AgentKeyFingerprint) {
		return fmt.Errorf("agentKeyFingerprint must be 16 lowercase hex characters, got %q", m.AgentKeyFingerprint)
	}
	if len(m.BackupSigningFingerprint) != 64 || !backupHexPattern.MatchString(m.BackupSigningFingerprint) {
		return fmt.Errorf("backupSigningFingerprint must be 64 lowercase hex characters, got %q", m.BackupSigningFingerprint)
	}
	if len(m.Tenants) == 0 {
		return fmt.Errorf("tenants is empty: a backup with no tenants is not worth keeping")
	}
	if len(m.Tenants) > backupMaxTenants {
		return fmt.Errorf("tenants has %d entries, the limit is %d", len(m.Tenants), backupMaxTenants)
	}
	seen := map[string]bool{}
	for i, tenant := range m.Tenants {
		if !backupSlugPattern.MatchString(tenant.Slug) {
			return fmt.Errorf("tenants[%d].slug %q must match ^[a-z0-9-]+$", i, tenant.Slug)
		}
		if seen[tenant.Slug] {
			return fmt.Errorf("tenants[%d].slug %q appears twice", i, tenant.Slug)
		}
		seen[tenant.Slug] = true
		if err := checkBackupText(fmt.Sprintf("tenants[%d].domain", i), tenant.Domain, 253, false); err != nil {
			return err
		}
		if tenant.SignerSHA256 != "" && !backupHexPattern.MatchString(strings.ToLower(
			strings.ReplaceAll(tenant.SignerSHA256, ":", ""))) {
			return fmt.Errorf("tenants[%d].signerSha256 is not hex", i)
		}
	}
	if len(m.InnerFiles) == 0 {
		return fmt.Errorf("innerFiles is empty: RECOVERY.md would have nothing to say")
	}
	if len(m.InnerFiles) > backupMaxInnerFile {
		return fmt.Errorf("innerFiles has %d entries, the limit is %d", len(m.InnerFiles), backupMaxInnerFile)
	}
	for i, file := range m.InnerFiles {
		if err := checkBackupPath(fmt.Sprintf("innerFiles[%d].path", i), file.Path); err != nil {
			return err
		}
		if err := checkBackupPath(fmt.Sprintf("innerFiles[%d].target", i), file.Target); err != nil {
			return err
		}
		if file.Size < 0 {
			return fmt.Errorf("innerFiles[%d].size is negative", i)
		}
		if len(file.SHA256) != 64 || !backupHexPattern.MatchString(file.SHA256) {
			return fmt.Errorf("innerFiles[%d].sha256 must be 64 lowercase hex characters", i)
		}
		if !backupModePattern.MatchString(file.Mode) {
			return fmt.Errorf("innerFiles[%d].mode %q must look like 0600", i, file.Mode)
		}
		if !backupOwnerPattern.MatchString(file.Owner) {
			return fmt.Errorf("innerFiles[%d].owner %q must look like user:group", i, file.Owner)
		}
	}
	return nil
}

func isBackupSlotName(slot string) bool {
	for _, name := range backupcontainer.SlotNames {
		if slot == name {
			return true
		}
	}
	return false
}

// checkBackupPath 挡的是「渲染进 recover.sh 之后变成一条命令」。
//
// 不做转义而是直接拒收：一条带 $(...)、反引号或换行的路径没有任何正当理由出现在
// 备份包里，它只可能是攻击，或者一个严重到必须让人看见的 bug。
func checkBackupPath(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is empty", field)
	}
	if len(value) > 512 {
		return fmt.Errorf("%s is %d bytes, the limit is 512", field, len(value))
	}
	if strings.ContainsAny(value, backupUnsafeInPath) {
		return fmt.Errorf("%s contains a character that would be interpreted by the shell; "+
			"paths in a backup package never need one", field)
	}
	// .. 会让 recover.sh 把文件写到目标目录外面
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return fmt.Errorf("%s contains '..'", field)
		}
	}
	return nil
}

func checkBackupText(field, value string, max int, required bool) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		if required {
			return fmt.Errorf("%s is required", field)
		}
		return nil
	}
	if len(trimmed) > max {
		return fmt.Errorf("%s is %d bytes, the limit is %d", field, len(trimmed), max)
	}
	if strings.ContainsAny(trimmed, backupUnsafeInPath) {
		return fmt.Errorf("%s contains a character that would be interpreted by the shell", field)
	}
	return nil
}
