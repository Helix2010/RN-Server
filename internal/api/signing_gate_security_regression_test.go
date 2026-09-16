package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
)

// 安全评审 R2 的三个 PoC 改写成的回归测试。

// manualUpload 以租户管理员身份走手工上传（POST /v1/admin/releases）：先把包放进存储、签发票据。
func (f *gateFixture) manualUpload(signer apkSigner, version string, buildNumber int) *httptest.ResponseRecorder {
	f.t.Helper()
	apk := buildSignedAPK(f.t, apkSpec{PackageName: f.packageName, VersionCode: buildNumber, VersionName: version, MinSDK: 24, ApplicationID: tenantApplicationID}, &signer)
	key := "manual/" + uniqueSuffix() + "/app.apk"
	token, err := f.s.encodeReleaseArtifactToken(releaseArtifactToken{ID: "art_" + uniqueSuffix(), TenantID: f.tenant, ObjectKey: key, FileName: "app.apk",
		ContentType: apkContentType, Size: int64(len(apk)), ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		f.t.Fatal(err)
	}
	f.store.put(key, apk, "etag-"+uniqueSuffix())
	c, recorder := testContext(f.t, f.tenant, http.MethodPost, "/v1/admin/releases", map[string]any{
		"artifactToken": token, "platform": "android", "version": version, "buildNumber": buildNumber, "releaseNotes": map[string]any{}, "mandatory": true,
	})
	f.s.createReleaseFromArtifact(c)
	return recorder
}

func (f *gateFixture) releaseCount() int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM app_releases WHERE tenant_id=?`, f.tenant).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *gateFixture) rejectedAudits(code string) int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action='release_rejected' AND JSON_UNQUOTE(JSON_EXTRACT(summary,'$.code'))=?`, f.tenant, code).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *gateFixture) putIdentity(packageName, signerSHA256 string) *httptest.ResponseRecorder {
	f.t.Helper()
	_, identityVersion := f.keystoreVersions()
	c, recorder := testContext(f.t, f.tenant, http.MethodPut, "/v1/admin/release-identity/android", map[string]any{
		"packageName": packageName, "signerSha256": signerSHA256, "expectedVersion": identityVersion, "reason": "rotate cert", "confirm": true,
	})
	f.s.updateAndroidReleaseIdentity(c)
	return recorder
}

// PoC-1a：租户管理员把登记的证书改成自己的，再手工上传自签的包。有 v3 密钥时登记身份只能是
// 密钥里的包名与证书；手工上传的自签包因此在身份比对上就被拒。
func TestDBTenantAdminCannotRepointTheReleaseIdentityAwayFromTheKeystore(t *testing.T) {
	f := newGateFixture(t, 111)
	attacker := newAPKSigner(t)
	if r := f.putIdentity(f.packageName, attacker.sha256()); r.Code != http.StatusConflict || problemCode(t, r) != "RELEASE_IDENTITY_KEYSTORE_MISMATCH" {
		t.Fatalf("repointing the identity to a foreign certificate: %d %s", r.Code, r.Body.String())
	}
	if r := f.putIdentity("com.other.app", f.apkSigner.sha256()); r.Code != http.StatusConflict || problemCode(t, r) != "RELEASE_IDENTITY_KEYSTORE_MISMATCH" {
		t.Fatalf("repointing the identity to another package: %d %s", r.Code, r.Body.String())
	}
	if r := f.putIdentity(f.packageName, f.apkSigner.sha256()); r.Code != http.StatusOK {
		t.Fatalf("saving the keystore's own identity again: %d %s", r.Code, r.Body.String())
	}
	if r := f.manualUpload(attacker, "9.9.9", 999); r.Code == http.StatusCreated || f.releaseCount() != 0 {
		t.Fatalf("BYPASS: a release signed with a key the signing gate never held was accepted: %d %s", r.Code, r.Body.String())
	}
	// 没有 v3 密钥的租户（还没迁到签名闸）照旧可以单独登记身份，但手工上传会被下一道闸挡住
	if _, err := f.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, f.tenant, buildKeystoreConfigKey); err != nil {
		t.Fatal(err)
	}
	if r := f.putIdentity(f.packageName, attacker.sha256()); r.Code != http.StatusOK {
		t.Fatalf("an identity without a v3 keystore: %d %s", r.Code, r.Body.String())
	}
	if r := f.manualUpload(attacker, "9.9.9", 999); r.Code != http.StatusConflict || problemCode(t, r) != "RELEASE_KEYSTORE_NOT_CONFIGURED" || f.rejectedAudits("RELEASE_KEYSTORE_NOT_CONFIGURED") != 1 {
		t.Fatalf("a manual upload without a v3 keystore: %d %s", r.Code, r.Body.String())
	}
}

// 库里 build.keystore 的外层索引被改过（KEYSTORE_RECORD_INVALID）时，不能拿篡改后的外层证书当依据：
// 单独改发布身份 409 BUILD_KEYSTORE_RECORD_INVALID；手工上传闸按"没有可用密钥"拒绝。
func TestDBReleaseIdentityCannotFollowATamperedKeystoreRecord(t *testing.T) {
	f := newGateFixture(t, 116)
	attacker := newAPKSigner(t)
	var original []byte
	if err := f.db.QueryRow(`SELECT config_value FROM app_configs WHERE tenant_id=? AND config_key=?`, f.tenant, buildKeystoreConfigKey).Scan(&original); err != nil {
		t.Fatal(err)
	}
	for name, tamper := range map[string]func(){
		"outer certificate replaced": func() { f.setKeystoreValue(`JSON_SET(config_value,'$.certificateSha256',?)`, attacker.sha256()) },
		"record malformed":           func() { f.setKeystoreValue(`JSON_SET(config_value,'$.unexpected',?)`, "field") },
	} {
		f.setKeystoreValue(`?`, string(original))
		tamper()
		if r := f.putIdentity(f.packageName, attacker.sha256()); r.Code != http.StatusConflict || problemCode(t, r) != "BUILD_KEYSTORE_RECORD_INVALID" {
			t.Fatalf("%s: the identity followed a tampered keystore record: %d %s", name, r.Code, r.Body.String())
		}
		if r := f.putIdentity(f.packageName, f.apkSigner.sha256()); r.Code != http.StatusConflict || problemCode(t, r) != "BUILD_KEYSTORE_RECORD_INVALID" {
			t.Fatalf("%s: an identity change was accepted while the keystore record is unusable: %d %s", name, r.Code, r.Body.String())
		}
	}
	// 发布身份也被直接改成了篡改后的证书：手工上传闸不采信用不了的记录
	var identity []byte
	if err := f.db.QueryRow(`SELECT config_value FROM app_configs WHERE tenant_id=? AND config_key=?`, f.tenant, releaseAndroidIdentityConfigKey).Scan(&identity); err != nil {
		t.Fatal(err)
	}
	f.setKeystoreValue(`?`, string(original))
	f.setKeystoreValue(`JSON_SET(config_value,'$.certificateSha256',?)`, attacker.sha256())
	if _, err := f.db.Exec(`UPDATE app_configs SET config_value=?,version=version+1 WHERE tenant_id=? AND config_key=?`,
		strings.Replace(string(identity), f.apkSigner.sha256(), attacker.sha256(), 1), f.tenant, releaseAndroidIdentityConfigKey); err != nil {
		t.Fatal(err)
	}
	if r := f.manualUpload(attacker, "9.9.9", 999); r.Code != http.StatusConflict || problemCode(t, r) != "RELEASE_KEYSTORE_NOT_CONFIGURED" || f.releaseCount() != 0 {
		t.Fatalf("a manual upload trusted a tampered keystore record: %d %s", r.Code, r.Body.String())
	}
	// 恢复之后照常
	f.setKeystoreValue(`?`, string(original))
	if _, err := f.db.Exec(`UPDATE app_configs SET config_value=?,version=version+1 WHERE tenant_id=? AND config_key=?`, identity, f.tenant, releaseAndroidIdentityConfigKey); err != nil {
		t.Fatal(err)
	}
	if r := f.putIdentity(f.packageName, f.apkSigner.sha256()); r.Code != http.StatusOK {
		t.Fatalf("the identity of a healthy keystore: %d %s", r.Code, r.Body.String())
	}
}

// PoC-1b：用签名闸公开的 X25519 公钥封一份自己的 v3 密文（服务端打不开内层，照收），把登记证书
// 连带换掉，再手工上传自签的包。主签名闸没有在本机确认这一版密钥，手工上传就拒绝并留审计；
// 运维真的在签名闸上确认过之后才放行。
func TestDBManualUploadRequiresACertificateConfirmedOnThePrimarySigner(t *testing.T) {
	f := newGateFixture(t, 112)
	attacker := newAPKSigner(t)
	keystoreVersion, identityVersion := f.keystoreVersions()
	if r := f.saveKeystoreRequest(map[string]any{
		"upload": f.keystoreUpload(f.slug, f.packageName, attacker.sha256(), f.primary, f.standby), "packageName": f.packageName,
		"signerSha256": attacker.sha256(), "expectedVersion": keystoreVersion, "releaseIdentityExpectedVersion": identityVersion,
		"reason": "rotate keystore", "confirm": true,
	}); r.Code != http.StatusOK {
		t.Fatalf("upload a keystore sealed to the signers' public keys: %d %s", r.Code, r.Body.String())
	}
	if r := f.manualUpload(attacker, "9.9.9", 999); r.Code != http.StatusConflict || problemCode(t, r) != "RELEASE_SIGNER_NOT_CONFIRMED" || f.releaseCount() != 0 {
		t.Fatalf("BYPASS: a self-signed release was accepted before the primary signer confirmed the certificate: %d %s", r.Code, r.Body.String())
	}
	if f.rejectedAudits("RELEASE_SIGNER_NOT_CONFIRMED") != 1 {
		t.Fatal("the refused manual upload was not audited")
	}
	// 解得开不等于确认过：确认是运维在签名闸上对照离线指纹做的
	f.reportCheck(f.primary, false, "pending")
	if r := f.manualUpload(attacker, "9.9.9", 999); r.Code != http.StatusConflict || problemCode(t, r) != "RELEASE_SIGNER_NOT_CONFIRMED" {
		t.Fatalf("a manual upload after decrypt=ok but before confirmation: %d %s", r.Code, r.Body.String())
	}
	// 备签名闸确认了不算，要主签名闸
	f.reportCheck(f.standby, true, "pending")
	if r := f.manualUpload(attacker, "9.9.9", 999); r.Code != http.StatusConflict || problemCode(t, r) != "RELEASE_SIGNER_NOT_CONFIRMED" {
		t.Fatalf("a manual upload confirmed only by the standby: %d %s", r.Code, r.Body.String())
	}
	f.reportCheck(f.primary, true, "pending")
	if r := f.manualUpload(attacker, "9.9.9", 999); r.Code != http.StatusCreated {
		t.Fatalf("a manual upload signed with the certificate the primary confirmed: %d %s", r.Code, r.Body.String())
	}
}

// 登记身份与 v3 密钥不一致（规则收紧之前存下的旧值）时，包按登记身份比对通过也不行：
// 签名证书必须就是密钥记录里的那张。
func TestDBManualUploadRequiresTheKeystoreCertificate(t *testing.T) {
	f := newGateFixture(t, 113)
	attacker := newAPKSigner(t)
	var raw []byte
	if err := f.db.QueryRow(`SELECT config_value FROM app_configs WHERE tenant_id=? AND config_key=?`, f.tenant, releaseAndroidIdentityConfigKey).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	legacy := strings.Replace(string(raw), f.apkSigner.sha256(), attacker.sha256(), 1)
	if _, err := f.db.Exec(`UPDATE app_configs SET config_value=?,version=version+1 WHERE tenant_id=? AND config_key=?`, legacy, f.tenant, releaseAndroidIdentityConfigKey); err != nil {
		t.Fatal(err)
	}
	if r := f.manualUpload(attacker, "9.9.9", 999); r.Code != http.StatusConflict || problemCode(t, r) != "RELEASE_SIGNER_KEYSTORE_MISMATCH" || f.releaseCount() != 0 {
		t.Fatalf("a package matching a stale identity but not the keystore: %d %s", r.Code, r.Body.String())
	}
	if f.rejectedAudits("RELEASE_SIGNER_KEYSTORE_MISMATCH") != 1 {
		t.Fatal("the refused manual upload was not audited")
	}
}

// PoC-2：签名闸待接受期间，偷到令牌的人把 Ed25519 换成自己的。接受时必须带 Ed25519 指纹，
// 按真机抄来的指纹接受会发现对不上。
func TestDBSignerKeysCannotBeAcceptedWithoutTheEd25519Fingerprint(t *testing.T) {
	f := newGateFixture(t, 114)
	created := f.adminDo(http.MethodPost, "/v1/admin/platform/machines", map[string]any{
		"role": "signer", "name": "signer-c-" + uniqueSuffix(), "signerRole": "standby",
		"expectedVersion": registryVersion(t, f), "reason": "new standby", "confirm": true,
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	body := decodeBody(t, created)
	token := body["token"].(string)
	id := body["machine"].(map[string]any)["id"].(string)
	real := newGateMachine(t, machineRoleSigner, "real")
	thief := newGateMachine(t, machineRoleSigner, "thief")
	report := func(x, ed []byte) int {
		return f.do(http.MethodPost, "/v1/signer/public-key", token, nil, map[string]any{
			"x25519PublicKey": base64.StdEncoding.EncodeToString(x), "ed25519PublicKey": base64.StdEncoding.EncodeToString(ed), "rotationSignature": nil,
		}).Code
	}
	realX := real.X25519.PublicKey().Bytes()
	if code := report(realX, real.ed25519Public()); code != http.StatusOK {
		t.Fatalf("real report: %d", code)
	}
	if code := report(realX, thief.ed25519Public()); code != http.StatusOK {
		t.Fatalf("thief report: %d", code)
	}
	accept := func(extra map[string]any) *httptest.ResponseRecorder {
		body := map[string]any{"publicKeySha256": fingerprint.SHA256Hex(realX), "expectedVersion": registryVersion(t, f), "reason": "checked on the box", "confirm": true}
		for k, v := range extra {
			body[k] = v
		}
		return f.adminDo(http.MethodPost, "/v1/admin/platform/machines/"+id+"/accept-key", body)
	}
	if r := accept(nil); r.Code != http.StatusBadRequest || problemCode(t, r) != "INVALID_MACHINE" {
		t.Fatalf("accepting a signer with only the X25519 fingerprint: %d %s", r.Code, r.Body.String())
	}
	if r := accept(map[string]any{"ed25519PublicKeySha256": fingerprint.SHA256Hex(real.ed25519Public())}); r.Code != http.StatusConflict || problemCode(t, r) != "MACHINE_KEY_MISMATCH" {
		t.Fatalf("accepting with the real Ed25519 fingerprint while the thief's key is pending: %d %s", r.Code, r.Body.String())
	}
	list := decodeBody(t, f.adminDo(http.MethodGet, "/v1/admin/platform/machines", nil))
	for _, item := range list["items"].([]any) {
		machine := item.(map[string]any)
		if machine["id"] == id && (machine["status"] != machineStatusPendingKey || machine["ed25519PublicKeySha256"] != nil) {
			t.Fatalf("the swapped key was accepted: %v", machine)
		}
	}
}

// PoC-3：机器上报的自由文本入库前去掉控制字符与双向覆盖字符（保留 \t）。
func TestDBMachineReportedTextIsSanitized(t *testing.T) {
	f := newGateFixture(t, 115)
	f.queueBuild("7.0.0", 80)
	job := f.claimBuild()
	id := job["id"].(string)
	evil := "ok\x1b[2J‮gnp.exe\r\nFAKE:\tsigner⁦approved‏"
	if r := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/fail", f.builder.Token, attemptHeaders(buildAttemptHeader, int(job["attempt"].(float64))), map[string]any{
		"failureReason": evil, "commitSha": "", "logTail": []string{evil},
	}); r.Code != http.StatusNoContent {
		t.Fatalf("fail: %d %s", r.Code, r.Body.String())
	}
	stored := f.jobStatus(id)
	want := "ok[2Jgnp.exeFAKE:\tsignerapproved"
	if stored.FailureReason.String != want {
		t.Fatalf("stored failure_reason %q, want %q", stored.FailureReason.String, want)
	}
	var tail []string
	if err := json.Unmarshal(stored.LogTail, &tail); err != nil || len(tail) != 1 || tail[0] != want {
		t.Fatalf("stored log_tail %q (%v)", stored.LogTail, err)
	}

	// 签名闸的拒签说明与检查错误同样清洗
	signed := f.queueBuild("7.1.0", 81)
	f.deliverBuild(f.claimBuild())
	if f.claimSign(f.primary) == nil {
		t.Fatal("nothing to sign")
	}
	if r := f.do(http.MethodPost, "/v1/signer/jobs/"+signed+"/reject", f.primary.Token, attemptHeaders(signAttemptHeader, 1), map[string]any{
		"kind": "violation", "code": "POLICY", "detail": evil,
	}); r.Code != http.StatusNoContent {
		t.Fatalf("reject: %d %s", r.Code, r.Body.String())
	}
	var outcome buildJobSignOutcome
	if err := json.Unmarshal(f.jobStatus(signed).SignOutcome, &outcome); err != nil || outcome.Detail != want {
		t.Fatalf("stored sign outcome detail %q (%v)", outcome.Detail, err)
	}
}

func TestSanitizeReportedText(t *testing.T) {
	for in, want := range map[string]string{
		"plain text":              "plain text",
		"tab\tkept":               "tab\tkept",
		"\x00\x07\x1b[31mred\x7f": "[31mred",
		"c1gone":                "c1gone",
		"‪‫‬‭‮bidi":               "bidi",
		"⁦⁧⁨⁩iso":                 "iso",
		"‎‏marks":                 "marks",
		"line1\r\nline2":          "line1line2",
		"中文​保留":                   "中文​保留",
	} {
		if got := sanitizeReportedText(in); got != want {
			t.Errorf("sanitizeReportedText(%q) = %q, want %q", in, got, want)
		}
	}
	if got := clipBytes("ab中文", 4); got != "ab" {
		t.Errorf("clipBytes cut a rune: %q", got)
	}
}
