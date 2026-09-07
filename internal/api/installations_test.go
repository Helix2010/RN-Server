package api

import (
	"strings"
	"testing"
)

func TestInstallationCredentialIsRandomAndHasHash(t *testing.T) {
	credential, hash, err := newInstallationCredential()
	if err != nil || len(credential) < 40 || len(hash) != 64 {
		t.Fatalf("invalid credential: %q %q %v", credential, hash, err)
	}
	other, _, _ := newInstallationCredential()
	if credential == other {
		t.Fatal("installation credentials must be random")
	}
}

func TestInstallationUpsertPlaceholderCount(t *testing.T) {
	head := installationUpsertSQL[:strings.Index(installationUpsertSQL, " ON DUPLICATE")]
	columns := head[strings.Index(head, "(")+1 : strings.Index(head, ")")]
	values := head[strings.LastIndex(head, "(")+1 : strings.LastIndex(head, ")")]
	columnCount, valueCount := len(strings.Split(columns, ",")), len(strings.Split(values, ","))
	if columnCount != valueCount {
		t.Fatalf("app_installations upsert lists %d columns but %d values", columnCount, valueCount)
	}
	if got := strings.Count(values, "?"); got != columnCount-1 {
		t.Fatalf("app_installations upsert expects %d placeholders (all columns except the status literal), got %d", columnCount-1, got)
	}
}

// 凭证查询必须按 (tenant, application_id, platform, installation_id) 定位：
// 只按 installation_id 查再 LIMIT 1，同一台设备有多条记录时会取错行，
// 有效凭证被判失效，App 反复重注册（线上曾把 credential_version 刷到 80）
func TestInstallationCredentialLookupIsScopedToApplicationAndPlatform(t *testing.T) {
	where := installationCredentialLookupSQL[strings.Index(installationCredentialLookupSQL, " WHERE "):]
	for _, column := range []string{"tenant_id=?", "application_id=?", "platform=?", "installation_id=?"} {
		if !strings.Contains(where, column) {
			t.Fatalf("credential lookup must filter by %s: %s", column, where)
		}
	}
	if got := strings.Count(where, "?"); got != 4 {
		t.Fatalf("credential lookup expects 4 placeholders, got %d", got)
	}
}
