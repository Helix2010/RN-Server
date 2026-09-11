package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/secretbox"
)

// 灰度发布的验收用例，编号对应
// RN-App/docs/design/canary-release-allowlist-2026-09-11.md §7。

func canaryTestServer(db *sql.DB) *server {
	s := testServer(db)
	box, err := secretbox.New(base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		panic(err)
	}
	s.secrets = box
	s.cfg.OTAChannel = "production"
	return s
}

// insertCanaryTestRelease 直接写一条可发布的发布记录：入库路径要真 APK，
// 这里要验的是读路径与状态机，不重复走校验。
func insertCanaryTestRelease(t *testing.T, db *sql.DB, tenant, id, version string, build int, status string, audience []string, mandatory bool) {
	t.Helper()
	now := time.Now().UTC()
	var raw any
	if audience != nil {
		encoded, _ := json.Marshal(audience)
		raw = encoded
	}
	notes, _ := json.Marshal(map[string][]string{"zh-CN": {"测试"}})
	metadata, _ := json.Marshal(map[string]any{"objectEtag": "etag-" + id, "size": 10})
	if _, err := db.Exec(`INSERT INTO app_releases(id,tenant_id,platform,version,build_number,runtime_version,status,canary_installations,release_notes,object_key,file_name,content_type,expected_size,file_size,sha256,file_metadata,mandatory,verified_at,created_by,created_at,updated_at) VALUES(?,?,'android',?,?,?,?,?,?,?,?,'application/vnd.android.package-archive',10,10,?,?,?,?,'tester',?,?)`,
		id, tenant, version, build, version, status, raw, notes, "objects/"+id, "app.apk", strings.Repeat("a", 64), metadata, mandatory, now, now, now); err != nil {
		t.Fatalf("insert release %s: %v", id, err)
	}
}

// canaryInstallation 注册一条真安装并返回它的凭证，供"带凭证的请求"用。
func canaryInstallation(t *testing.T, s *server, tenant, installationID string) string {
	t.Helper()
	credential, hash, err := newInstallationCredential()
	if err != nil {
		t.Fatalf("new credential: %v", err)
	}
	c, _ := testContext(t, tenant, http.MethodPost, "/v1/mobile/installations/heartbeat", nil)
	c.Request.Header.Set("x-platform", "android")
	c.Request.Header.Set("x-application-id", "dex-mobile")
	c.Request.Header.Set("x-app-version", "1.3.0")
	c.Request.Header.Set("x-build-number", "26")
	c.Request.Header.Set("x-runtime-version", "1.3.0")
	c.Request.Header.Set("x-distribution-channel", "direct")
	body := installationHeartbeat{InstallationID: installationID, DeviceSourceHash: strings.Repeat("d", 64), PackageID: "com.example.app", OTAChannel: "production", Locale: "zh-CN", Theme: "system", OSVersion: "35", DeviceClass: "android-phone"}
	if code, detail := normalizeRuntimeReport(&body); code != "" {
		t.Fatalf("runtime report invalid: %s %s", code, detail)
	}
	if err := s.saveInstallation(c, body, hash, 1, time.Now().UTC().Add(24*time.Hour), time.Now().UTC()); err != nil {
		t.Fatalf("save installation: %v", err)
	}
	return credential
}

// runReleaseAction 走真实的 releaseAction 处理函数（路由参数照实填）。
func runReleaseAction(t *testing.T, s *server, tenant, id, action string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	c, recorder := testContext(t, tenant, http.MethodPost, "/v1/admin/releases/"+id+"/"+action, body)
	c.Params = gin.Params{{Key: "id", Value: id}, {Key: "action", Value: action}}
	s.releaseAction(c)
	return recorder
}

// withInstallationIdentity 给请求装上 App 真实会发的那组身份头。
func withInstallationIdentity(header http.Header, installationID, credential string) {
	header.Set("x-platform", "android")
	header.Set("x-application-id", "dex-mobile")
	header.Set("x-installation-id", installationID)
	if credential != "" {
		header.Set("Authorization", "Installation "+credential)
	}
}

// 1 / 2 / 3 / 13 / 15：名单内拿到灰度，名单外与身份认不出的一律只拿 active。
func TestDBCanaryVisibilityFollowsVerifiedIdentity(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(41)
	s := canaryTestServer(db)
	insider, outsider := "inst_canary_in_"+uniqueSuffix(), "inst_canary_out_"+uniqueSuffix()
	insiderCredential := canaryInstallation(t, s, tenant, insider)
	outsiderCredential := canaryInstallation(t, s, tenant, outsider)
	insertCanaryTestRelease(t, db, tenant, "rel_active_"+uniqueSuffix(), "1.3.0", 26, "active", nil, false)
	insertCanaryTestRelease(t, db, tenant, "rel_canary_"+uniqueSuffix(), "1.4.0", 27, "canary", []string{insider}, false)

	cases := []struct {
		name        string
		id          string
		credential  string
		wantVersion string
		wantStatus  string
	}{
		{"名单内且凭证有效", insider, insiderCredential, "1.4.0", "canary"},
		{"名单外", outsider, outsiderCredential, "1.3.0", "active"},
		{"不带任何身份", "", "", "1.3.0", "active"},
		{"带 ID 不带凭证（复制别人的安装 ID）", insider, "", "1.3.0", "active"},
		{"凭证是伪造的", insider, "icred_" + strings.Repeat("x", 43), "1.3.0", "active"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			c, _ := testContext(t, tenant, http.MethodGet, "/v1/mobile/bootstrap", nil)
			if item.id != "" {
				withInstallationIdentity(c.Request.Header, item.id, item.credential)
			}
			audience := s.canaryAudienceID(c, tenant)
			visible, err := s.visibleSimplifiedRelease(c.Request.Context(), tenant, "android", audience)
			if err != nil {
				t.Fatalf("visible release: %v", err)
			}
			if visible.Version != item.wantVersion || visible.Status != item.wantStatus {
				t.Fatalf("got %s/%s, want %s/%s", visible.Version, visible.Status, item.wantVersion, item.wantStatus)
			}
		})
	}
}

// 14：安装被吊销后灰度立即失效。
func TestDBCanaryStopsAtRevokedInstallation(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(42)
	s := canaryTestServer(db)
	installation := "inst_canary_revoke_" + uniqueSuffix()
	credential := canaryInstallation(t, s, tenant, installation)
	insertCanaryTestRelease(t, db, tenant, "rel_active_"+uniqueSuffix(), "1.3.0", 26, "active", nil, false)
	insertCanaryTestRelease(t, db, tenant, "rel_canary_"+uniqueSuffix(), "1.4.0", 27, "canary", []string{installation}, false)
	c, _ := testContext(t, tenant, http.MethodGet, "/v1/mobile/bootstrap", nil)
	withInstallationIdentity(c.Request.Header, installation, credential)
	if s.canaryAudienceID(c, tenant) != installation {
		t.Fatal("credential must be accepted before revocation")
	}
	if _, err := db.Exec(`UPDATE app_installations SET status='revoked',credential_revoked_at=? WHERE tenant_id=? AND installation_id=?`, time.Now().UTC(), tenant, installation); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if audience := s.canaryAudienceID(c, tenant); audience != "" {
		t.Fatalf("revoked installation must not match a canary audience, got %q", audience)
	}
}

// 7：灰度期间发一个新的全量版本，灰度行不被收尾；名单内设备按 build 取大的那个。
func TestDBCanarySurvivesAFullPublishAndLosesToAHigherBuild(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(43)
	s := canaryTestServer(db)
	installation := "inst_canary_race_" + uniqueSuffix()
	canaryInstallation(t, s, tenant, installation)
	canaryID := "rel_canary_" + uniqueSuffix()
	insertCanaryTestRelease(t, db, tenant, "rel_active_"+uniqueSuffix(), "1.3.0", 26, "active", nil, false)
	insertCanaryTestRelease(t, db, tenant, canaryID, "1.4.0", 27, "canary", []string{installation}, false)
	newActive := "rel_next_" + uniqueSuffix()
	insertCanaryTestRelease(t, db, tenant, newActive, "1.5.0", 28, "verified", nil, false)

	if recorder := runReleaseAction(t, s, tenant, newActive, "publish", map[string]any{"reason": "ship it", "confirm": true}); recorder.Code != http.StatusCreated {
		t.Fatalf("publish failed: %d %s", recorder.Code, recorder.Body.String())
	}
	var canaryStatus string
	if err := db.QueryRow(`SELECT status FROM app_releases WHERE tenant_id=? AND id=?`, tenant, canaryID).Scan(&canaryStatus); err != nil || canaryStatus != "canary" {
		t.Fatalf("canary row must survive a full publish, got %q (%v)", canaryStatus, err)
	}
	visible, err := s.visibleSimplifiedRelease(context.Background(), tenant, "android", installation)
	if err != nil || visible.Version != "1.5.0" {
		t.Fatalf("higher build must win, got %v (%v)", visible.Version, err)
	}
}

// 8 / 9 / 10：转灰度的三条约束与转正。
func TestDBCanaryTransitionRules(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(44)
	s := canaryTestServer(db)
	installation := "inst_canary_rules_" + uniqueSuffix()
	canaryInstallation(t, s, tenant, installation)

	t.Run("名单为空时转灰度被拒", func(t *testing.T) {
		id := "rel_empty_" + uniqueSuffix()
		insertCanaryTestRelease(t, db, tenant, id, "2.0.0", 40, "verified", nil, false)
		recorder := runReleaseAction(t, s, tenant, id, "canary", map[string]any{"reason": "canary", "confirm": true, "installations": []string{}})
		if recorder.Code != 422 || !strings.Contains(recorder.Body.String(), "CANARY_AUDIENCE_REQUIRED") {
			t.Fatalf("want CANARY_AUDIENCE_REQUIRED, got %d %s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("名单里有不存在的安装被拒", func(t *testing.T) {
		id := "rel_unknown_" + uniqueSuffix()
		insertCanaryTestRelease(t, db, tenant, id, "2.1.0", 41, "verified", nil, false)
		recorder := runReleaseAction(t, s, tenant, id, "canary", map[string]any{"reason": "canary", "confirm": true, "installations": []string{installation, "inst_typo"}})
		if recorder.Code != 422 || !strings.Contains(recorder.Body.String(), "CANARY_INSTALLATION_UNKNOWN") {
			t.Fatalf("want CANARY_INSTALLATION_UNKNOWN, got %d %s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("强制升级的版本不能转灰度", func(t *testing.T) {
		id := "rel_mandatory_" + uniqueSuffix()
		insertCanaryTestRelease(t, db, tenant, id, "2.2.0", 42, "verified", nil, true)
		recorder := runReleaseAction(t, s, tenant, id, "canary", map[string]any{"reason": "canary", "confirm": true, "installations": []string{installation}})
		if recorder.Code != 409 || !strings.Contains(recorder.Body.String(), "CANARY_MANDATORY_FORBIDDEN") {
			t.Fatalf("want CANARY_MANDATORY_FORBIDDEN, got %d %s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("灰度记录不能再设强制升级", func(t *testing.T) {
		id := "rel_lock_" + uniqueSuffix()
		insertCanaryTestRelease(t, db, tenant, id, "2.3.0", 43, "canary", []string{installation}, false)
		recorder := runReleaseAction(t, s, tenant, id, "set-mandatory", map[string]any{"reason": "force it", "confirm": true, "mandatory": true})
		if recorder.Code != 409 || !strings.Contains(recorder.Body.String(), "RELEASE_FLAG_LOCKED") {
			t.Fatalf("want RELEASE_FLAG_LOCKED, got %d %s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("转灰度后再转正：同一条记录变 active，旧 active 被收尾，名单清空", func(t *testing.T) {
		old := "rel_old_active_" + uniqueSuffix()
		insertCanaryTestRelease(t, db, tenant, old, "2.4.0", 44, "active", nil, false)
		id := "rel_promote_" + uniqueSuffix()
		insertCanaryTestRelease(t, db, tenant, id, "2.5.0", 45, "verified", nil, false)
		if recorder := runReleaseAction(t, s, tenant, id, "canary", map[string]any{"reason": "canary first", "confirm": true, "installations": []string{installation}}); recorder.Code != http.StatusCreated {
			t.Fatalf("canary failed: %d %s", recorder.Code, recorder.Body.String())
		}
		var status string
		var audience []byte
		if err := db.QueryRow(`SELECT status,canary_installations FROM app_releases WHERE tenant_id=? AND id=?`, tenant, id).Scan(&status, &audience); err != nil || status != "canary" {
			t.Fatalf("want canary, got %q (%v)", status, err)
		}
		if got := canaryAudienceOf(audience); len(got) != 1 || got[0] != installation {
			t.Fatalf("audience not persisted: %v", got)
		}
		if recorder := runReleaseAction(t, s, tenant, id, "promote", map[string]any{"reason": "promote it", "confirm": true}); recorder.Code != http.StatusCreated {
			t.Fatalf("promote failed: %d %s", recorder.Code, recorder.Body.String())
		}
		if err := db.QueryRow(`SELECT status,canary_installations FROM app_releases WHERE tenant_id=? AND id=?`, tenant, id).Scan(&status, &audience); err != nil || status != "active" {
			t.Fatalf("want active after promote, got %q (%v)", status, err)
		}
		if audience != nil {
			t.Fatalf("audience must be cleared when leaving canary, got %s", audience)
		}
		var oldStatus string
		if err := db.QueryRow(`SELECT status FROM app_releases WHERE tenant_id=? AND id=?`, tenant, old).Scan(&oldStatus); err != nil || oldStatus != "completed" {
			t.Fatalf("promote must complete the previous active, got %q (%v)", oldStatus, err)
		}
		var audits int
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND target_id=? AND action IN ('canary','promote')`, tenant, id).Scan(&audits); err != nil || audits != 2 {
			t.Fatalf("both canary and promote must be audited, got %d (%v)", audits, err)
		}
	})

	t.Run("改名单：不动状态，名单落库并进审计", func(t *testing.T) {
		other := "inst_canary_rules_2_" + uniqueSuffix()
		canaryInstallation(t, s, tenant, other)
		id := "rel_audience_" + uniqueSuffix()
		insertCanaryTestRelease(t, db, tenant, id, "2.7.0", 47, "canary", []string{installation}, false)
		if recorder := runReleaseAction(t, s, tenant, id, "set-canary-audience", map[string]any{"reason": "换一批测试机", "confirm": true, "installations": []string{other}}); recorder.Code != http.StatusCreated {
			t.Fatalf("set-canary-audience failed: %d %s", recorder.Code, recorder.Body.String())
		}
		var status string
		var audience []byte
		if err := db.QueryRow(`SELECT status,canary_installations FROM app_releases WHERE tenant_id=? AND id=?`, tenant, id).Scan(&status, &audience); err != nil || status != "canary" {
			t.Fatalf("status must stay canary, got %q (%v)", status, err)
		}
		if got := canaryAudienceOf(audience); len(got) != 1 || got[0] != other {
			t.Fatalf("audience not replaced: %v", got)
		}
		var audits int
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND target_id=? AND action='release_set_canary_audience'`, tenant, id).Scan(&audits); err != nil || audits != 1 {
			t.Fatalf("audience change must be audited, got %d (%v)", audits, err)
		}
		// 非灰度记录不能改名单
		other2 := "rel_audience_active_" + uniqueSuffix()
		insertCanaryTestRelease(t, db, tenant, other2, "2.8.0", 48, "active", nil, false)
		recorder := runReleaseAction(t, s, tenant, other2, "set-canary-audience", map[string]any{"reason": "试试看", "confirm": true, "installations": []string{other}})
		if recorder.Code != 409 || !strings.Contains(recorder.Body.String(), "INVALID_TRANSITION") {
			t.Fatalf("want INVALID_TRANSITION, got %d %s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("取消灰度", func(t *testing.T) {
		id := "rel_cancel_" + uniqueSuffix()
		insertCanaryTestRelease(t, db, tenant, id, "2.6.0", 46, "canary", []string{installation}, false)
		if recorder := runReleaseAction(t, s, tenant, id, "cancel-canary", map[string]any{"reason": "bad build", "confirm": true}); recorder.Code != http.StatusCreated {
			t.Fatalf("cancel failed: %d %s", recorder.Code, recorder.Body.String())
		}
		var status string
		var audience []byte
		if err := db.QueryRow(`SELECT status,canary_installations FROM app_releases WHERE tenant_id=? AND id=?`, tenant, id).Scan(&status, &audience); err != nil || status != "rejected" || audience != nil {
			t.Fatalf("want rejected with a cleared audience, got %q/%s (%v)", status, audience, err)
		}
		visible, err := s.visibleSimplifiedRelease(context.Background(), tenant, "android", installation)
		if err == nil && visible.Version == "2.6.0" {
			t.Fatal("a cancelled canary must stop being visible")
		}
	})
}

// 5 / 6：下载接口与 bootstrap 用同一套可见性。
func TestDBCanaryDownloadFollowsTheSameVisibility(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(45)
	s := canaryTestServer(db)
	insider, outsider := "inst_dl_in_"+uniqueSuffix(), "inst_dl_out_"+uniqueSuffix()
	insiderCredential := canaryInstallation(t, s, tenant, insider)
	outsiderCredential := canaryInstallation(t, s, tenant, outsider)
	canaryID := "rel_dl_canary_" + uniqueSuffix()
	insertCanaryTestRelease(t, db, tenant, canaryID, "3.0.0", 50, "canary", []string{insider}, false)

	// 只验可见性判定（真下载还要对象存储）：查询命中 = 允许下载
	visible := func(installationID, credential string) bool {
		c, _ := testContext(t, tenant, http.MethodGet, "/v1/public/releases/"+canaryID+"/download", nil)
		withInstallationIdentity(c.Request.Header, installationID, credential)
		audience := s.canaryAudienceID(c, tenant)
		var key string
		err := db.QueryRow(`SELECT object_key FROM app_releases WHERE tenant_id=? AND id=? AND `+canaryVisibleSQL, tenant, canaryID, audience, audience).Scan(&key)
		return err == nil
	}
	if !visible(insider, insiderCredential) {
		t.Fatal("an allowlisted device must be able to download the canary build")
	}
	if visible(outsider, outsiderCredential) {
		t.Fatal("guessing the release id must not be enough to download a canary build")
	}
}

// 11 / 16 / 17：OTA manifest 的身份来自短时令牌。
func TestDBCanaryOTAManifestUsesTheShortLivedToken(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(46)
	s := canaryTestServer(db)
	insider := "inst_ota_in_" + uniqueSuffix()
	canaryInstallation(t, s, tenant, insider)
	base := "rel_ota_base_" + uniqueSuffix()
	insertCanaryTestRelease(t, db, tenant, base, "4.0.0", 60, "active", nil, false)
	now := time.Now().UTC()
	insertCanaryTestOTA(t, db, tenant, "ota_active_"+uniqueSuffix(), base, 1, "active", nil, now)
	insertCanaryTestOTA(t, db, tenant, "ota_canary_"+uniqueSuffix(), base, 2, "canary", []string{insider}, now)

	revisionFor := func(header string) int {
		c, _ := testContext(t, tenant, http.MethodGet, "/v1/ota/manifest", nil)
		if header != "" {
			c.Request.Header.Set("Expo-Extra-Params", header)
		}
		audience := s.canaryAudienceFromExtraParams(c, tenant)
		var revision int
		if err := db.QueryRow(`SELECT o.revision FROM ota_releases o WHERE o.tenant_id=? AND o.platform='android' AND o.channel='production' AND o.runtime_version='4.0.0' AND `+canaryVisibleOTASQL+` ORDER BY o.revision DESC LIMIT 1`, tenant, audience, audience).Scan(&revision); err != nil {
			t.Fatalf("manifest lookup: %v", err)
		}
		return revision
	}
	token, err := s.encodeCanaryToken(tenant, insider, now)
	if err != nil {
		t.Fatalf("encode token: %v", err)
	}
	if got := revisionFor(canaryExtraParamKey + `="` + token + `"`); got != 2 {
		t.Fatalf("an allowlisted device must see the canary revision, got %d", got)
	}
	if got := revisionFor(""); got != 1 {
		t.Fatalf("without a token the device must stay on active, got %d", got)
	}
	expired, err := s.encodeCanaryToken(tenant, insider, now.Add(-canaryTokenTTL-time.Minute))
	if err != nil {
		t.Fatalf("encode expired token: %v", err)
	}
	if got := revisionFor(canaryExtraParamKey + `="` + expired + `"`); got != 1 {
		t.Fatalf("an expired token must fall back to active, got %d", got)
	}
	if got := revisionFor(canaryExtraParamKey + `="` + strings.Repeat("A", 64) + `"`); got != 1 {
		t.Fatalf("a forged token must fall back to active, got %d", got)
	}
	// 另一个租户签发的令牌解不开：AAD 把它绑死在租户上
	if other := s.decodeCanaryToken(testTenant(47), token); other != "" {
		t.Fatalf("a token must not decode under another tenant, got %q", other)
	}
}

func insertCanaryTestOTA(t *testing.T, db *sql.DB, tenant, id, base string, revision int, status string, audience []string, now time.Time) {
	t.Helper()
	var raw any
	if audience != nil {
		encoded, _ := json.Marshal(audience)
		raw = encoded
	}
	if _, err := db.Exec(`INSERT INTO ota_releases(id,tenant_id,base_release_id,platform,channel,runtime_version,revision,update_id,release_kind,status,canary_installations,manifest_key,manifest_sha256,release_notes,created_by,published_at,created_at,updated_at) VALUES(?,?,?,'android','production','4.0.0',?,?,'update',?,?,?,?,'{}','tester',?,?,?)`,
		id, tenant, base, revision, randomUUID(), status, raw, "objects/"+id+"/manifest.json", strings.Repeat("b", 64), now, now, now); err != nil {
		t.Fatalf("insert ota %s: %v", id, err)
	}
}

// 灰度令牌是认证加密，不是签名：改一个字节就解不开，客户端也读不出里面的安装 ID。
func TestCanaryTokenIsOpaqueAndTamperEvident(t *testing.T) {
	s := &server{cfg: config.Config{}}
	box, err := secretbox.New(base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	if err != nil {
		t.Fatalf("secretbox: %v", err)
	}
	s.secrets = box
	token, err := s.encodeCanaryToken("42", "inst_secret", time.Now().UTC())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if strings.Contains(token, "inst_secret") {
		t.Fatal("the installation id must not be readable from the token")
	}
	if got := s.decodeCanaryToken("42", token); got != "inst_secret" {
		t.Fatalf("round trip failed, got %q", got)
	}
	tampered := []byte(token)
	tampered[len(tampered)-1] ^= 'A' ^ 'B'
	if got := s.decodeCanaryToken("42", string(tampered)); got != "" {
		t.Fatalf("a tampered token must not decode, got %q", got)
	}
	if got := s.decodeCanaryToken("42", "not base64 $$"); got != "" {
		t.Fatalf("garbage must not decode, got %q", got)
	}
	if got := s.decodeCanaryToken("42", ""); got != "" {
		t.Fatalf("an empty token must not decode, got %q", got)
	}
}

// Expo-Extra-Params 是 RFC 8941 结构化字典；解析要能从多成员里挑出自己那条。
func TestStructuredDictionaryString(t *testing.T) {
	cases := []struct {
		name, header, key, want string
	}{
		{"单成员", `canary-token="abc-_123"`, "canary-token", "abc-_123"},
		{"多成员", `other="x", canary-token="tok", more="y"`, "canary-token", "tok"},
		{"引号内的逗号不切分", `other="a,b", canary-token="tok"`, "canary-token", "tok"},
		{"转义引号", `canary-token="a\"b"`, "canary-token", `a"b`},
		{"裸 token 形式", `canary-token=tok`, "canary-token", "tok"},
		{"带参数的裸 token", `canary-token=tok;p=1`, "canary-token", "tok"},
		{"键不存在", `other="x"`, "canary-token", ""},
		{"空头", ``, "canary-token", ""},
		{"未闭合引号", `canary-token="abc`, "canary-token", ""},
		{"非法转义", `canary-token="a\nb"`, "canary-token", ""},
		{"引号后有尾巴", `canary-token="a"b`, "canary-token", ""},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			if got := structuredDictionaryString(item.header, item.key); got != item.want {
				t.Fatalf("got %q, want %q", got, item.want)
			}
		})
	}
}

func TestNormalizeCanaryAudience(t *testing.T) {
	audience, code, _ := normalizeCanaryAudience([]string{" a ", "b", "a", "", "  "})
	if code != "" {
		t.Fatalf("unexpected rejection: %s", code)
	}
	if len(audience) != 2 || audience[0] != "a" || audience[1] != "b" {
		t.Fatalf("trim/dedup/order broken: %v", audience)
	}
	if _, code, _ := normalizeCanaryAudience(nil); code != "CANARY_AUDIENCE_REQUIRED" {
		t.Fatalf("an empty audience must be rejected, got %q", code)
	}
	if _, code, _ := normalizeCanaryAudience([]string{"   ", ""}); code != "CANARY_AUDIENCE_REQUIRED" {
		t.Fatalf("a blank-only audience must be rejected, got %q", code)
	}
	if _, code, _ := normalizeCanaryAudience([]string{strings.Repeat("x", 121)}); code != "CANARY_AUDIENCE_INVALID" {
		t.Fatalf("an over-long id must be rejected, got %q", code)
	}
	oversized := make([]string, canaryAudienceLimit+1)
	for i := range oversized {
		oversized[i] = "inst_" + strconv.Itoa(i)
	}
	if _, code, _ := normalizeCanaryAudience(oversized); code != "CANARY_AUDIENCE_TOO_LARGE" {
		t.Fatalf("an oversized audience must be rejected, got %q", code)
	}
}

// 名单为空 / NULL 的灰度行对谁都不可见——出错的方向永远是"少发"。
func TestCanaryAudienceForStatusHidesNonCanaryRows(t *testing.T) {
	if got := canaryAudienceForStatus("active", []byte(`["a"]`)); got != nil {
		t.Fatalf("a non-canary row must not report an audience, got %v", got)
	}
	if got := canaryAudienceForStatus("canary", nil); len(got) != 0 || got == nil {
		t.Fatalf("a canary row with no audience must report an empty list, got %v", got)
	}
	if got := canaryAudienceOf([]byte("not json")); got != nil {
		t.Fatalf("a corrupt audience must read as empty, got %v", got)
	}
}

// 4：公开的 latest 接口在匿名时只返回 active；带上有效凭证的名单内设备才看得到灰度。
func TestDBCanaryPublicLatestIsAnonymousSafe(t *testing.T) {
	db := openTestDB(t)
	tenant := testTenant(48)
	s := canaryTestServer(db)
	installation := "inst_latest_" + uniqueSuffix()
	credential := canaryInstallation(t, s, tenant, installation)
	insertCanaryTestRelease(t, db, tenant, "rel_latest_active_"+uniqueSuffix(), "5.0.0", 70, "active", nil, false)
	insertCanaryTestRelease(t, db, tenant, "rel_latest_canary_"+uniqueSuffix(), "5.1.0", 71, "canary", []string{installation}, false)

	latest := func(id, cred string) map[string]any {
		c, recorder := testContext(t, tenant, http.MethodGet, "/v1/public/releases/latest?platform=android", nil)
		if id != "" {
			withInstallationIdentity(c.Request.Header, id, cred)
		}
		s.publicLatestReleaseFromDomain(c)
		if recorder.Code != http.StatusOK {
			t.Fatalf("latest failed: %d %s", recorder.Code, recorder.Body.String())
		}
		return decodeBody(t, recorder)
	}
	if got := latest("", "")["version"]; got != "5.0.0" {
		t.Fatalf("an anonymous request must only ever see active, got %v", got)
	}
	body := latest(installation, credential)
	if body["version"] != "5.1.0" || body["status"] != "canary" {
		t.Fatalf("an allowlisted device must see the canary build, got %v/%v", body["version"], body["status"])
	}
}
