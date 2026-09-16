package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// 读和写回的是同一个资源，管理端两处用同一个 schema 解析。少键的表现是：服务端明明存好了，
// 界面却报"上传失败"，而错误说的是字段类型不对。
func TestDBBuildKeystoreReadAndWriteReturnTheSameShape(t *testing.T) {
	f := newGateFixture(t, 31)
	keystoreVersion, identityVersion := f.keystoreVersions()
	written := f.saveKeystoreRequest(map[string]any{
		"upload": f.keystoreUpload(f.slug, f.packageName, f.apkSigner.sha256(), f.primary, f.standby), "packageName": f.packageName,
		"signerSha256": f.apkSigner.sha256(), "expectedVersion": keystoreVersion, "releaseIdentityExpectedVersion": identityVersion,
		"reason": "re-seal for both signers", "confirm": true,
	})
	if written.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", written.Code, written.Body.String())
	}
	write := decodeBody(t, written)
	c, recorder := testContext(t, f.tenant, http.MethodGet, "/v1/admin/build-keystore", nil)
	f.s.getBuildKeystore(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("read failed: %d %s", recorder.Code, recorder.Body.String())
	}
	read := decodeBody(t, recorder)
	for key := range read {
		if _, ok := write[key]; !ok {
			t.Fatalf("the write response is missing %q, which every reader of this resource expects", key)
		}
	}
	if write["releaseIdentityVersion"] != float64(identityVersion+1) {
		t.Fatalf("releaseIdentityVersion = %v", write["releaseIdentityVersion"])
	}
	if read["configured"] != true || read["format"] != float64(3) || read["legacy"] != false || read["version"] != float64(keystoreVersion+1) {
		t.Fatalf("read view: %v", read)
	}
	if read["certificateSha256"] != f.apkSigner.sha256() || read["packageName"] != f.packageName || read["keyAlias"] != "release" {
		t.Fatalf("read view identity: %v", read)
	}
	recipients := read["recipients"].([]any)
	if len(recipients) != 2 {
		t.Fatalf("recipients: %v", recipients)
	}
	for _, item := range recipients {
		entry := item.(map[string]any)
		if entry["machineId"] != f.primary.ID && entry["machineId"] != f.standby.ID {
			t.Fatalf("a recipient is not mapped to its signer: %v", entry)
		}
	}
	if missing := read["missingSigners"].([]any); len(missing) != 0 {
		t.Fatalf("no signer should be missing: %v", missing)
	}
	// 重新上传之后确认记录绑在旧版本上，不就绪；视图里的 digest 仍然算得出来
	if read["ready"] != false || read["trustRootsDigest"] != f.currentDigest() {
		t.Fatalf("a fresh keystore version cannot be ready yet: ready=%v digest=%v", read["ready"], read["trustRootsDigest"])
	}
	// 审计记指纹与收件人，不记密文
	var summary string
	if err := f.db.QueryRow(`SELECT summary FROM audit_events WHERE tenant_id=? AND action='build_keystore_update' ORDER BY created_at DESC LIMIT 1`, f.tenant).Scan(&summary); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(summary, `"ct"`) || strings.Contains(summary, "sealed") || !strings.Contains(summary, f.primary.recipient()) {
		t.Fatalf("keystore audit summary: %s", summary)
	}
}

// v1（口令封）、v2（加密给打包机公钥）以及夹着别的版本密文的文件一律 422，不是 400：
// 控制台要能告诉人"这是旧格式，重新生成"，而不是"字段不认识"。
func TestDBBuildKeystoreRefusesEverythingButV3(t *testing.T) {
	f := newGateFixture(t, 32)
	keystoreVersion, identityVersion := f.keystoreVersions()
	base := func(upload any) map[string]any {
		return map[string]any{"upload": upload, "packageName": f.packageName, "signerSha256": f.apkSigner.sha256(),
			"expectedVersion": keystoreVersion, "releaseIdentityExpectedVersion": identityVersion, "reason": "legacy upload", "confirm": true}
	}
	legacyV1 := map[string]any{
		"sealed":   map[string]any{"v": 1, "kdf": "scrypt", "n": 65536, "r": 8, "p": 1, "salt": "c2FsdA==", "nonce": "bm9uY2U=", "ciphertext": "Y2lwaGVy"},
		"keyAlias": "anyfun", "keystoreSha256": strings.Repeat("a", 64), "expectedVersion": keystoreVersion, "reason": "legacy", "confirm": true,
	}
	if r := f.saveKeystoreRequest(legacyV1); r.Code != http.StatusUnprocessableEntity || problemCode(t, r) != "BUILD_KEYSTORE_FORMAT_UNSUPPORTED" {
		t.Fatalf("a v1 passphrase box was not refused as unsupported: %d %s", r.Code, r.Body.String())
	}
	legacyV2 := map[string]any{"v": 2, "alg": "x25519-hkdf-sha256-aes256gcm", "kid": "0123456789abcdef", "epk": "x", "nonce": "x", "ciphertext": "x"}
	if r := f.saveKeystoreRequest(map[string]any{"sealed": legacyV2, "keyAlias": "a", "keystoreSha256": strings.Repeat("a", 64)}); r.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a v2 build-agent box was not refused: %d %s", r.Code, r.Body.String())
	}
	upload := f.keystoreUpload(f.slug, f.packageName, f.apkSigner.sha256(), f.primary)
	oldFormat := upload
	oldFormat.Format = "rn-android-keystore-upload/v2"
	if r := f.saveKeystoreRequest(base(oldFormat)); r.Code != http.StatusUnprocessableEntity || problemCode(t, r) != "BUILD_KEYSTORE_FORMAT_UNSUPPORTED" {
		t.Fatalf("an upload in another format was accepted: %d %s", r.Code, r.Body.String())
	}
	mixed := f.keystoreUpload(f.slug, f.packageName, f.apkSigner.sha256(), f.primary)
	mixed.Boxes[0].Version = 2
	if r := f.saveKeystoreRequest(base(mixed)); r.Code != http.StatusUnprocessableEntity || problemCode(t, r) != "BUILD_KEYSTORE_FORMAT_UNSUPPORTED" {
		t.Fatalf("a v3 upload carrying a v2 box was accepted: %d %s", r.Code, r.Body.String())
	}
}

// 收件人不在已登记（非吊销）签名闸里的多余密文直接拒收；缺某台签名闸只提示。
func TestDBBuildKeystoreRecipients(t *testing.T) {
	f := newGateFixture(t, 33)
	keystoreVersion, identityVersion := f.keystoreVersions()
	stranger := newGateMachine(t, machineRoleSigner, "stranger-"+uniqueSuffix())
	body := func(recipients ...gateMachine) map[string]any {
		return map[string]any{"upload": f.keystoreUpload(f.slug, f.packageName, f.apkSigner.sha256(), recipients...), "packageName": f.packageName,
			"signerSha256": f.apkSigner.sha256(), "expectedVersion": keystoreVersion, "releaseIdentityExpectedVersion": identityVersion,
			"reason": "recipient test", "confirm": true}
	}
	if r := f.saveKeystoreRequest(body(f.primary, stranger)); r.Code != http.StatusUnprocessableEntity ||
		problemCode(t, r) != "BUILD_KEYSTORE_RECIPIENT_UNKNOWN" || !strings.Contains(r.Body.String(), stranger.recipient()) {
		t.Fatalf("a box for an unregistered key was accepted: %d %s", r.Code, r.Body.String())
	}
	// 吊销的签名闸同样不算已登记
	revoked := f.standby.record(signerRoleStandby)
	revoked.Status = machineStatusRevoked
	f.writeMachines(f.builder.record(""), f.primary.record(signerRolePrimary), revoked)
	if r := f.saveKeystoreRequest(body(f.primary, f.standby)); r.Code != http.StatusUnprocessableEntity || problemCode(t, r) != "BUILD_KEYSTORE_RECIPIENT_UNKNOWN" {
		t.Fatalf("a box for a revoked signer was accepted: %d %s", r.Code, r.Body.String())
	}
	// 缺一台（新登记、还没重新 seal 的备签名闸）：收下，并在视图里说出来
	f.writeMachines(f.builder.record(""), f.primary.record(signerRolePrimary), f.standby.record(signerRoleStandby))
	r := f.saveKeystoreRequest(body(f.primary))
	if r.Code != http.StatusOK {
		t.Fatalf("an upload missing the standby was refused: %d %s", r.Code, r.Body.String())
	}
	missing := decodeBody(t, r)["missingSigners"].([]any)
	if len(missing) != 1 || missing[0].(map[string]any)["machineId"] != f.standby.ID {
		t.Fatalf("missingSigners = %v", missing)
	}
}

// 文件里的租户、包名、证书必须与这个租户、请求里登记的发布身份一致；作废的旧指纹永久拒绝。
func TestDBBuildKeystoreIdentityAndTenantChecks(t *testing.T) {
	f := newGateFixture(t, 34)
	keystoreVersion, identityVersion := f.keystoreVersions()
	request := func(slug, filePackage, fileCertificate, packageName, signer string) map[string]any {
		return map[string]any{"upload": f.keystoreUpload(slug, filePackage, fileCertificate, f.primary), "packageName": packageName,
			"signerSha256": signer, "expectedVersion": keystoreVersion, "releaseIdentityExpectedVersion": identityVersion,
			"reason": "identity test", "confirm": true}
	}
	certificate := f.apkSigner.sha256()
	cases := []struct {
		name, code string
		status     int
		body       map[string]any
	}{
		{"other tenant", "BUILD_KEYSTORE_TENANT_MISMATCH", 422, request("some-other-tenant", f.packageName, certificate, f.packageName, certificate)},
		{"package differs", "BUILD_KEYSTORE_IDENTITY_MISMATCH", 422, request(f.slug, f.packageName, certificate, "com.other.app", certificate)},
		{"signer differs", "BUILD_KEYSTORE_IDENTITY_MISMATCH", 422, request(f.slug, f.packageName, certificate, f.packageName, strings.Repeat("d", 64))},
		{"retired anyfun", "RELEASE_SIGNER_RETIRED", 422, request(f.slug, f.packageName, "1a5d9fb446e2f4c8e1aa464a02b14248a265ea9c554f83eb01ec94886329e694", f.packageName, "1a5d9fb446e2f4c8e1aa464a02b14248a265ea9c554f83eb01ec94886329e694")},
		{"retired predict-kim", "RELEASE_SIGNER_RETIRED", 422, request(f.slug, f.packageName, "9ab5fbe6e2052bbd8ce502a8d442b3e5d4769de8d5fa939cec480bc2d1ffcf37", f.packageName, "9ab5fbe6e2052bbd8ce502a8d442b3e5d4769de8d5fa939cec480bc2d1ffcf37")},
	}
	for _, tc := range cases {
		if r := f.saveKeystoreRequest(tc.body); r.Code != tc.status || problemCode(t, r) != tc.code {
			t.Fatalf("%s: %d %s", tc.name, r.Code, r.Body.String())
		}
	}
	stale := request(f.slug, f.packageName, certificate, f.packageName, certificate)
	stale["expectedVersion"] = keystoreVersion - 1
	if r := f.saveKeystoreRequest(stale); r.Code != http.StatusConflict || problemCode(t, r) != "STALE_BUILD_KEYSTORE" {
		t.Fatalf("a stale keystore version was accepted: %d %s", r.Code, r.Body.String())
	}
	staleIdentity := request(f.slug, f.packageName, certificate, f.packageName, certificate)
	staleIdentity["releaseIdentityExpectedVersion"] = identityVersion + 5
	if r := f.saveKeystoreRequest(staleIdentity); r.Code != http.StatusConflict || problemCode(t, r) != "STALE_RELEASE_IDENTITY" {
		t.Fatalf("a stale release identity version was accepted: %d %s", r.Code, r.Body.String())
	}
}

// 旧格式的记录读出来视为"没有可用的签名密钥"：控制台显示 legacy，就绪判断不通过；
// 带着这一行的版本号上传 v3 就能覆盖它。
func TestDBBuildKeystoreLegacyRecordIsNotConfigured(t *testing.T) {
	f := newGateFixture(t, 35)
	if _, err := f.db.Exec(`UPDATE app_configs SET config_value=?,version=version+1 WHERE tenant_id=? AND config_key=?`,
		`{"sealed":"eA==","keyAlias":"a","keystoreSha256":"`+strings.Repeat("b", 64)+`"}`, f.tenant, buildKeystoreConfigKey); err != nil {
		t.Fatal(err)
	}
	c, recorder := testContext(t, f.tenant, http.MethodGet, "/v1/admin/build-keystore", nil)
	f.s.getBuildKeystore(c)
	view := decodeBody(t, recorder)
	if recorder.Code != http.StatusOK || view["legacy"] != true || view["configured"] != false || view["format"] != nil || view["ready"] != false {
		t.Fatalf("legacy view: %d %v", recorder.Code, view)
	}
	f.uploadKeystore(f.primary, f.standby)
	if state, err := f.s.buildKeystoreStateFor(c.Request.Context(), f.db, f.tenant); err != nil || !state.configured() {
		t.Fatalf("the legacy row was not replaced: %v %+v", err, state)
	}
}

// 就绪判断逐条说清缺什么：每条原因带固定的 code（控制台按它给处理入口），全部对上才就绪。
// 用例把每个 code 都触发一次，新增原因忘了加进枚举或 OpenAPI 时这里会失败。
func TestDBSignerReadinessExplainsEachGap(t *testing.T) {
	f := newGateFixture(t, 36)
	seen := map[string]bool{}
	readiness := func() signerReadiness {
		t.Helper()
		r, err := f.s.signerReadinessFor(t.Context(), f.tenant)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range r.Problems {
			if !containsString(readinessProblemCodes, p.Code) || strings.TrimSpace(p.Detail) == "" {
				t.Fatalf("a readiness problem outside the enum or without detail: %+v", p)
			}
			seen[p.Code] = true
		}
		return r
	}
	expect := func(code string) {
		t.Helper()
		r := readiness()
		for _, p := range r.Problems {
			if p.Code == code {
				if r.Ready {
					t.Fatalf("ready with a problem: %+v", r.Problems)
				}
				return
			}
		}
		t.Fatalf("expected %s, got ready=%v %+v", code, r.Ready, r.Problems)
	}
	expectReady := func() {
		t.Helper()
		if r := readiness(); !r.Ready || len(r.Problems) != 0 {
			t.Fatalf("expected ready, got %+v", r.Problems)
		}
	}
	setConfig := func(key string, value any) {
		t.Helper()
		raw, _ := json.Marshal(value)
		if _, err := f.db.Exec(`UPDATE app_configs SET config_value=?,version=version+1 WHERE tenant_id=? AND config_key=?`, raw, f.tenant, key); err != nil {
			t.Fatal(err)
		}
	}
	report := func(item map[string]any) {
		t.Helper()
		keystoreVersion, _ := f.keystoreVersions()
		base := map[string]any{"tenantSlug": f.slug, "keystoreVersion": keystoreVersion, "decrypt": "ok", "confirmed": true,
			"confirmedTrustRootsDigest": f.currentDigest(), "trialSign": "ok", "error": nil}
		for k, v := range item {
			base[k] = v
		}
		if r := f.do(http.MethodPost, "/v1/signer/keystore-checks", f.primary.Token, nil, map[string]any{"localRole": f.localRoleOf(f.primary), "items": []any{base}}); r.Code != http.StatusNoContent {
			t.Fatalf("report: %d %s", r.Code, r.Body.String())
		}
	}
	expectReady()
	c, recorder := testContext(t, f.tenant, http.MethodGet, "/v1/admin/build-keystore", nil)
	f.s.getBuildKeystore(c)
	if problems, ok := decodeBody(t, recorder)["readinessProblems"].([]any); !ok || len(problems) != 0 {
		t.Fatalf("a ready tenant must report an empty readinessProblems array: %s", recorder.Body.String())
	}

	report(map[string]any{"trialSign": "pending"})
	expect(readinessPrimaryTrialSignPending)
	report(map[string]any{"trialSign": "failed", "error": "apksigner exited 1"})
	expect(readinessPrimaryTrialSignFailed)
	report(map[string]any{"confirmed": false, "confirmedTrustRootsDigest": nil})
	expect(readinessPrimaryNotConfirmed)
	report(map[string]any{"decrypt": "failed", "error": "box does not open"})
	expect(readinessPrimaryDecryptFailed)
	report(nil)
	expectReady()

	// 控制台视图与排队门禁带同样的 code
	report(map[string]any{"trialSign": "pending"})
	c, recorder = testContext(t, f.tenant, http.MethodGet, "/v1/admin/build-keystore", nil)
	f.s.getBuildKeystore(c)
	if body := recorder.Body.String(); !strings.Contains(body, `"code":"`+readinessPrimaryTrialSignPending+`"`) {
		t.Fatalf("the keystore view does not carry the problem code: %s", body)
	}
	c, recorder = testContext(t, f.tenant, http.MethodPost, "/v1/admin/builds", map[string]any{
		"platform": "android", "gitRef": "main", "version": "9.9.9", "buildNumber": 999, "reason": "not ready", "confirm": true,
		"releaseNotes": map[string]any{"zh-CN": []string{"测试"}},
	})
	f.s.createBuildJob(c)
	if recorder.Code != http.StatusConflict || problemCode(t, recorder) != "SIGNER_NOT_READY" ||
		!strings.Contains(recorder.Body.String(), `"code":"`+readinessPrimaryTrialSignPending+`"`) {
		t.Fatalf("queue gate: %d %s", recorder.Code, recorder.Body.String())
	}
	report(nil)
	expectReady()

	identity := appIdentity{AppName: "Seeded", Scheme: "seeded", APIBaseURL: "https://api.seeded.example"}
	buildCfg := func(id appIdentity) buildConfig {
		return buildConfig{RepoDirectory: f.slug, DefaultGitRef: buildGitRef, Identity: id}
	}
	// 改了 apiBaseUrl：确认过的信任根摘要对不上；重新确认之后就绪
	changed := identity
	changed.APIBaseURL = "https://api2.seeded.example"
	setConfig(buildConfigKey, buildCfg(changed))
	expect(readinessTrustRootsChanged)
	report(nil)
	expectReady()
	// 校验收紧之前存下的 :443
	withPort := identity
	withPort.APIBaseURL = "https://api.seeded.example:443"
	setConfig(buildConfigKey, buildCfg(withPort))
	expect(readinessAPIBaseURLInvalid)
	// scheme 不是自定义 scheme：信任根不合法
	badScheme := identity
	badScheme.Scheme = "https"
	setConfig(buildConfigKey, buildCfg(badScheme))
	expect(readinessTrustRootsInvalid)
	// App 身份缺字段
	incomplete := identity
	incomplete.APIBaseURL = ""
	setConfig(buildConfigKey, buildCfg(incomplete))
	expect(readinessAppIdentityIncomplete)
	setConfig(buildConfigKey, buildCfg(changed))
	expectReady()

	// 发布身份与密钥不一致、没登记
	var rawIdentity []byte
	if err := f.db.QueryRow(`SELECT config_value FROM app_configs WHERE tenant_id=? AND config_key=?`, f.tenant, releaseAndroidIdentityConfigKey).Scan(&rawIdentity); err != nil {
		t.Fatal(err)
	}
	var identityValue map[string]any
	_ = json.Unmarshal(rawIdentity, &identityValue)
	mismatched := map[string]any{}
	for k, v := range identityValue {
		mismatched[k] = v
	}
	mismatched["signerSha256"] = strings.Repeat("d", 64)
	setConfig(releaseAndroidIdentityConfigKey, mismatched)
	expect(readinessReleaseIdentityMismatch)
	if _, err := f.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, f.tenant, releaseAndroidIdentityConfigKey); err != nil {
		t.Fatal(err)
	}
	expect(readinessReleaseIdentityMissing)
	if _, err := f.db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,9,'tester',UTC_TIMESTAMP(3))`,
		f.tenant, releaseAndroidIdentityConfigKey, rawIdentity); err != nil {
		t.Fatal(err)
	}
	expectReady()

	// 控制台上的主签名闸本机记录不是主
	notPromoted := f.primary.record(signerRolePrimary)
	notPromoted.ReportedLocalRole = signerRoleStandby
	f.writeMachines(f.builder.record(""), notPromoted, f.standby.record(signerRoleStandby))
	expect(readinessPrimaryLocalRole)
	f.writeMachines(f.builder.record(""), f.primary.record(signerRolePrimary), f.standby.record(signerRoleStandby))
	expectReady()

	// 主签名闸没检查过当前版本、没有收到密文、没有主签名闸
	if _, err := f.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, f.tenant, buildKeystoreCheckConfigKey); err != nil {
		t.Fatal(err)
	}
	expect(readinessPrimaryCheckMissing)
	f.uploadKeystore(f.standby)
	expect(readinessPrimarySignerNoBox)
	f.writeMachines(f.builder.record(""), f.primary.record(signerRoleStandby), f.standby.record(signerRoleStandby))
	expect(readinessPrimarySignerMissing)

	// OTA 证书没了
	if _, err := f.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, f.tenant, otaSigningConfigKey); err != nil {
		t.Fatal(err)
	}
	expect(readinessOTACertificateMissing)

	// 记录用不了：只改外层的证书指纹，与密文文件对不上
	if _, err := f.db.Exec(`UPDATE app_configs SET config_value=JSON_SET(config_value,'$.certificateSha256',?),version=version+1 WHERE tenant_id=? AND config_key=?`,
		strings.Repeat("e", 64), f.tenant, buildKeystoreConfigKey); err != nil {
		t.Fatal(err)
	}
	expect(readinessKeystoreRecordInvalid)

	// 旧格式、没有签名密钥
	if _, err := f.db.Exec(`UPDATE app_configs SET config_value=?,version=version+1 WHERE tenant_id=? AND config_key=?`,
		`{"sealed":"eA==","keyAlias":"a","keystoreSha256":"`+strings.Repeat("b", 64)+`"}`, f.tenant, buildKeystoreConfigKey); err != nil {
		t.Fatal(err)
	}
	expect(readinessKeystoreLegacyFormat)
	if _, err := f.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, f.tenant, buildKeystoreConfigKey); err != nil {
		t.Fatal(err)
	}
	expect(readinessKeystoreNotConfigured)

	for _, code := range readinessProblemCodes {
		if !seen[code] {
			t.Errorf("readiness problem %s was never produced by this test", code)
		}
	}
}
