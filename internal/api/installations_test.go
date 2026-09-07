package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
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

// 心跳里"设备实际在跑什么"的字段：内置包不能带 update id，OTA 包必须带合法 update id，
// 缺 launchSource 时不能单独带 update id；不符直接 422，不静默丢弃
func TestNormalizeRuntimeReport(t *testing.T) {
	str := func(v string) *string { return &v }
	cases := []struct {
		name   string
		body   installationHeartbeat
		code   string
		source string
		id     string
	}{
		{name: "absent fields stay nil", body: installationHeartbeat{}},
		{name: "embedded without id", body: installationHeartbeat{LaunchSource: str("Embedded")}, source: "embedded"},
		{name: "ota with uuid", body: installationHeartbeat{LaunchSource: str("ota"), RunningUpdateID: str("7C5C1363-8685-42B2-864E-38B6790471CA")}, source: "ota", id: "7c5c1363-8685-42b2-864e-38b6790471ca"},
		{name: "embedded with id rejected", body: installationHeartbeat{LaunchSource: str("embedded"), RunningUpdateID: str("7c5c1363-8685-42b2-864e-38b6790471ca")}, code: "OTA_RUNNING_UPDATE_INVALID"},
		{name: "ota without id rejected", body: installationHeartbeat{LaunchSource: str("ota")}, code: "OTA_RUNNING_UPDATE_INVALID"},
		{name: "ota with junk id rejected", body: installationHeartbeat{LaunchSource: str("ota"), RunningUpdateID: str("rev-5")}, code: "OTA_RUNNING_UPDATE_INVALID"},
		{name: "unknown source rejected", body: installationHeartbeat{LaunchSource: str("store")}, code: "OTA_RUNNING_UPDATE_INVALID"},
		{name: "id without source rejected", body: installationHeartbeat{RunningUpdateID: str("7c5c1363-8685-42b2-864e-38b6790471ca")}, code: "OTA_RUNNING_UPDATE_INVALID"},
		{name: "session state normalized", body: installationHeartbeat{SessionState: str(" Signed_In ")}},
		{name: "session state rejected", body: installationHeartbeat{SessionState: str("logged")}, code: "INVALID_INSTALLATION"},
	}
	for _, tc := range cases {
		body := tc.body
		code, _ := normalizeRuntimeReport(&body)
		if code != tc.code {
			t.Fatalf("%s: expected code %q, got %q", tc.name, tc.code, code)
		}
		if tc.code != "" {
			continue
		}
		if tc.source == "" && body.LaunchSource != nil {
			t.Fatalf("%s: launch source must stay nil", tc.name)
		}
		if tc.source != "" && (body.LaunchSource == nil || *body.LaunchSource != tc.source) {
			t.Fatalf("%s: launch source not normalized: %v", tc.name, body.LaunchSource)
		}
		if tc.id == "" && body.RunningUpdateID != nil {
			t.Fatalf("%s: running update id must be nil", tc.name)
		}
		if tc.id != "" && (body.RunningUpdateID == nil || *body.RunningUpdateID != tc.id) {
			t.Fatalf("%s: running update id not normalized: %v", tc.name, body.RunningUpdateID)
		}
		if tc.name == "session state normalized" && (body.SessionState == nil || *body.SessionState != "signed_in") {
			t.Fatalf("session state not normalized: %v", body.SessionState)
		}
	}
}

func TestInstallationCursorRoundTrip(t *testing.T) {
	at := time.Date(2026, 9, 7, 3, 16, 30, 805_000_000, time.UTC)
	cursor := encodeInstallationCursor(at, 42)
	decodedAt, id, err := decodeInstallationCursor(cursor)
	if err != nil || id != 42 || !decodedAt.Equal(at) {
		t.Fatalf("cursor round trip failed: %v %d %v", decodedAt, id, err)
	}
	if _, _, err := decodeInstallationCursor("not-a-cursor"); err == nil {
		t.Fatal("garbage cursor must be rejected")
	}
}

func TestParseInstallationListFilterRejectsInvalidValues(t *testing.T) {
	now := time.Now().UTC()
	for _, query := range []string{"platform=web", "launchSource=store", "runningOtaRevision=-1", "runningOtaRevision=five", "activeWithin=2d", "limit=0", "limit=201", "cursor=%25%25"} {
		recorder := httptest.NewRecorder()
		context, _ := gin.CreateTestContext(recorder)
		context.Request = httptest.NewRequest(http.MethodGet, "/v1/admin/installations?"+query, nil)
		if _, invalid := parseInstallationListFilter(context, now); invalid == "" {
			t.Fatalf("query %q must be rejected", query)
		}
	}
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	context.Request = httptest.NewRequest(http.MethodGet, "/v1/admin/installations?platform=android&launchSource=unreported&runningOtaRevision=5&activeWithin=7d&limit=20&q=inst_8b", nil)
	filter, invalid := parseInstallationListFilter(context, now)
	if invalid != "" {
		t.Fatalf("valid query rejected: %s", invalid)
	}
	where, args := filter.where("100000001")
	for _, fragment := range []string{"i.tenant_id=?", "i.platform=?", "i.launch_source IS NULL", "i.running_ota_revision=?", "i.last_active_at>=?", "i.installation_id LIKE ?"} {
		if !strings.Contains(where, fragment) {
			t.Fatalf("where clause missing %s: %s", fragment, where)
		}
	}
	if len(args) != 6 || filter.limit != 20 {
		t.Fatalf("unexpected args %v limit %d", args, filter.limit)
	}
}
