package api

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/machinesetup"
	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/recovery"
	"github.com/gin-gonic/gin"
)

// 签名闸自动化（设计 android-signing-gate-automation-2026-09-16 第 9 节「服务端」、ADR-0020）的库测。
// 没有一条依赖机器快慢：过期用改库里的时间表达，并发注册只断言结果（恰好一个成功），不断言耗时。

// ---- 夹具补充 ----

// installBundles 在临时目录里摆一份部署好的安装包（current 软链指向一个提交目录），返回两个归档的原始字节。
func (f *gateFixture) installBundles() map[string][]byte {
	f.t.Helper()
	root := f.t.TempDir()
	release := filepath.Join(root, "0123abcd")
	if err := os.MkdirAll(release, 0o755); err != nil {
		f.t.Fatal(err)
	}
	archives := map[string][]byte{}
	bundles := map[string]any{}
	for _, role := range []string{machineRoleSigner, machineRoleBuilder} {
		archive := []byte("archive of the " + role + " bundle " + randomID(12))
		binary := []byte("binary " + role)
		archives[role] = archive
		if err := os.WriteFile(filepath.Join(release, role+".tar.gz"), archive, 0o644); err != nil {
			f.t.Fatal(err)
		}
		files := []any{map[string]any{"name": "bin/" + role, "size": len(binary), "sha256": sha256HexBytes(binary)}}
		if role == machineRoleSigner {
			files = append(files, map[string]any{"name": "templates/rn-signer-@INSTANCE@-check@.service", "size": len(binary), "sha256": sha256HexBytes(binary)})
		}
		bundles[role] = map[string]any{
			"archive": role + ".tar.gz", "archiveSha256": sha256HexBytes(archive), "archiveSize": len(archive), "files": files,
		}
	}
	manifest, _ := json.Marshal(map[string]any{"format": machineBundleManifestFormat, "commit": "0123abcd", "bundles": bundles})
	if err := os.WriteFile(filepath.Join(release, machineBundleManifest), manifest, 0o644); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(release, filepath.Join(root, "current")); err != nil {
		f.t.Fatal(err)
	}
	f.s.machineBundleDir = filepath.Join(root, "current")
	return archives
}

func (f *gateFixture) describe(code string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.do(http.MethodPost, "/v1/machine-setup/describe", "", nil, map[string]any{"code": code})
}

// machineRecord 读登记里的一台机器。
func (f *gateFixture) machineRecord(id string) buildMachine {
	f.t.Helper()
	snapshot, err := readMachineRegistry(context.Background(), f.db, false)
	if err != nil {
		f.t.Fatal(err)
	}
	index, found := snapshot.Doc.find(id)
	if !found {
		f.t.Fatalf("machine %s is not registered", id)
	}
	return snapshot.Doc.Machines[index]
}

// machineView 从控制台列表里取一台机器的视图。
func (f *gateFixture) machineView(id string) map[string]any {
	f.t.Helper()
	for _, entry := range decodeBody(f.t, f.adminDo(http.MethodGet, "/v1/admin/platform/machines", nil))["items"].([]any) {
		if view := entry.(map[string]any); view["id"] == id {
			return view
		}
	}
	f.t.Fatalf("machine %s is not listed", id)
	return nil
}

// mutateRegistry 直接改库里的登记（模拟时间流逝等），绕过接口。
func (f *gateFixture) mutateRegistry(mutate func(doc *buildMachinesDoc)) {
	f.t.Helper()
	snapshot, err := readMachineRegistry(context.Background(), f.db, false)
	if err != nil {
		f.t.Fatal(err)
	}
	mutate(&snapshot.Doc)
	f.writeMachines(snapshot.Doc.Machines...)
}

// sealedUpload 造一份 v3 上传文件，加密给任意 X25519 公钥（签名闸或恢复公钥）。
func (f *gateFixture) sealedUpload(slug, packageName, alias, certificate string, recipients ...[]byte) keystorebox.Upload {
	f.t.Helper()
	fingerprints := []string{}
	for _, r := range recipients {
		fingerprints = append(fingerprints, fingerprint.SHA256Hex(r))
	}
	sort.Strings(fingerprints)
	p12 := make([]byte, 256)
	_, _ = rand.Read(p12)
	plaintext := keystorebox.Plaintext{
		Purpose: keystorebox.Purpose, TenantSlug: slug, PackageName: packageName, CertificateSHA256: certificate,
		KeyAlias: alias, Recipients: fingerprints, CreatedAt: "2026-09-16T00:00:00Z",
		P12Base64: base64.StdEncoding.EncodeToString(p12), StorePassword: "test-store-password", KeyPassword: "test-key-password",
	}
	upload := keystorebox.Upload{
		Format: keystorebox.UploadFormat, TenantSlug: slug, PackageName: packageName, KeyAlias: alias,
		CertificateSHA256: certificate, CreatedAt: "2026-09-16T00:00:00Z",
	}
	for _, r := range recipients {
		box, err := keystorebox.Seal(plaintext, r)
		if err != nil {
			f.t.Fatalf("seal: %v", err)
		}
		upload.Boxes = append(upload.Boxes, box)
	}
	return upload
}

func (f *gateFixture) generate(body map[string]any) *httptest.ResponseRecorder {
	f.t.Helper()
	c, recorder := testContext(f.t, f.tenant, http.MethodPost, "/v1/admin/build-keystore/generate", body)
	f.s.generateBuildKeystore(c)
	return recorder
}

func (f *gateFixture) generateBody(packageName string) map[string]any {
	keystoreVersion, identityVersion := f.keystoreVersions()
	return map[string]any{"packageName": packageName, "expectedVersion": keystoreVersion, "releaseIdentityExpectedVersion": identityVersion,
		"reason": "generate a signing key on the signer", "confirm": true}
}

// deliver 以 machine 身份交回一份生成的密钥，签名用 signer 的私钥。
func (f *gateFixture) deliver(machine gateMachine, requestID string, upload keystorebox.Upload, generatorID string, signer ed25519.PrivateKey) *httptest.ResponseRecorder {
	f.t.Helper()
	signature, err := keystorebox.SignGeneration(signer, requestID, upload)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.deliverSigned(machine, requestID, upload, generatorID, signature)
}

func (f *gateFixture) deliverSigned(machine gateMachine, requestID string, upload keystorebox.Upload, generatorID, signature string) *httptest.ResponseRecorder {
	f.t.Helper()
	generatorKey := fingerprint.SHA256Hex(machine.ed25519Public())
	if generatorID == f.standby.ID {
		generatorKey = fingerprint.SHA256Hex(f.standby.ed25519Public())
	}
	return f.do(http.MethodPost, "/v1/signer/keystore-generations/"+requestID, machine.Token, nil, map[string]any{
		"upload": upload, "generator": map[string]any{"machineId": generatorID, "ed25519PublicKeySha256": generatorKey}, "signature": signature,
	})
}

// checkItem 取签名闸检查接口里本夹具租户那一项（测试库里别的租户的项不看）；没有返回 nil。
func (f *gateFixture) checkItem(machine gateMachine) map[string]any {
	f.t.Helper()
	r := f.do(http.MethodGet, "/v1/signer/keystore-checks", machine.Token, nil, nil)
	if r.Code != http.StatusOK {
		f.t.Fatalf("keystore checks: %d %s", r.Code, r.Body.String())
	}
	var found map[string]any
	for _, entry := range decodeBody(f.t, r)["items"].([]any) {
		item := entry.(map[string]any)
		if item["tenantSlug"] == f.slug {
			if found != nil {
				f.t.Fatalf("the tenant is listed twice: %s", r.Body.String())
			}
			found = item
		}
	}
	return found
}

func (f *gateFixture) keystoreView() map[string]any {
	f.t.Helper()
	c, recorder := testContext(f.t, f.tenant, http.MethodGet, "/v1/admin/build-keystore", nil)
	f.s.getBuildKeystore(c)
	if recorder.Code != http.StatusOK {
		f.t.Fatalf("keystore view: %d %s", recorder.Code, recorder.Body.String())
	}
	return decodeBody(f.t, recorder)
}

func (f *gateFixture) storedGenerationRequest() keystoreGenerationRequest {
	f.t.Helper()
	raw, _, err := configRowVersion(context.Background(), f.db, f.tenant, buildKeystoreRequestConfigKey, false)
	if err != nil {
		f.t.Fatal(err)
	}
	request, err := parseGenerationRequest(raw)
	if err != nil || request == nil {
		f.t.Fatalf("stored generation request: %v %v", request, err)
	}
	return *request
}

// revokeRecoveryKey 以平台管理员身份吊销一把恢复公钥。
func (f *gateFixture) revokeRecoveryKey(id string) {
	f.t.Helper()
	snapshot, err := readRecoveryKeys(context.Background(), f.db, false)
	if err != nil {
		f.t.Fatal(err)
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/recovery-keys/"+id+"/revoke", map[string]any{"expectedVersion": snapshot.Version, "reason": "rotated", "confirm": true}); r.Code != http.StatusOK {
		f.t.Fatalf("revoke recovery key: %d %s", r.Code, r.Body.String())
	}
}

func (f *gateFixture) auditCount(tenant, action string) int {
	f.t.Helper()
	var count int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND action=?`, tenant, action).Scan(&count); err != nil {
		f.t.Fatal(err)
	}
	return count
}

func readinessCodes(t *testing.T, f *gateFixture) []string {
	t.Helper()
	r, err := f.s.signerReadinessFor(t.Context(), f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	codes := []string{}
	for _, p := range r.Problems {
		codes = append(codes, p.Code)
	}
	return codes
}

func newCertificateSHA256() string {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	return hex.EncodeToString(raw)
}

// ---- 注册码 ----

// 注册码一次性：describe 不消耗，enroll 消耗；过期、已用、作废的码一律同一句 404；重发作废旧码；
// 已注册、已吊销的机器不能重发。注册之后是 pending_key，接受公钥后令牌可用。
func TestDBEnrollmentCodeIsOneTimeExpiresAndCanBeReissued(t *testing.T) {
	f := newGateFixture(t, 120)
	f.installBundles()
	id, code := f.createMachine(machineRoleBuilder, "builder-enroll-"+uniqueSuffix(), nil)
	view := f.machineView(id)
	if view["status"] != machineStatusPendingEnrollment || view["enrollmentExpiresAt"] == nil || view["pendingPublicKeySha256"] != nil {
		t.Fatalf("a new machine's view: %v", view)
	}
	for i := 0; i < 2; i++ {
		if r := f.describe(code); r.Code != http.StatusOK || decodeBody(t, r)["machineId"] != id {
			t.Fatalf("describe #%d: %d %s", i, r.Code, r.Body.String())
		}
	}
	for name, bad := range map[string]string{"malformed": "rne_short", "unknown": "rne_" + strings.Repeat("A", 43), "empty": ""} {
		if r := f.describe(bad); r.Code != http.StatusNotFound || problemCode(t, r) != "ENROLLMENT_CODE_INVALID" {
			t.Fatalf("describe with a %s code: %d %s", name, r.Code, r.Body.String())
		}
	}
	if r := f.do(http.MethodPost, "/v1/machine-setup/describe", "", nil, map[string]any{"code": code, "extra": true}); r.Code != http.StatusBadRequest {
		t.Fatalf("describe with an unknown field: %d %s", r.Code, r.Body.String())
	}

	machine := newGateMachine(t, machineRoleBuilder, "unused")
	enrolled := f.enroll(code, nil, machine.ed25519Public())
	if enrolled.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", enrolled.Code, enrolled.Body.String())
	}
	result := decodeBody(t, enrolled)
	token, _ := result["token"].(string)
	if result["machineId"] != id || result["status"] != machineStatusPendingKey || !validMachineTokenShape(token) || enrolled.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("enroll result: %v", result)
	}
	record := f.machineRecord(id)
	if record.Status != machineStatusPendingKey || record.TokenSHA256 != sha256Hex(token) || record.Enrollment == nil || record.Enrollment.UsedAt == "" ||
		record.Pending == nil || record.Pending.PublicKeySHA256 != fingerprint.SHA256Hex(machine.ed25519Public()) || record.Pending.Ed25519PublicKey != "" {
		t.Fatalf("registry after enroll: %+v %+v", record, record.Pending)
	}
	// 已用的码：describe、enroll、下载安装包都是同一句 404
	if r := f.describe(code); r.Code != http.StatusNotFound || problemCode(t, r) != "ENROLLMENT_CODE_INVALID" {
		t.Fatalf("describe with a used code: %d %s", r.Code, r.Body.String())
	}
	if r := f.enroll(code, nil, newGateMachine(t, machineRoleBuilder, "x").ed25519Public()); r.Code != http.StatusNotFound || problemCode(t, r) != "ENROLLMENT_CODE_INVALID" {
		t.Fatalf("enroll with a used code: %d %s", r.Code, r.Body.String())
	}
	if r := f.do(http.MethodGet, "/v1/machine-setup/bundle/builder.tar.gz", "", map[string]string{enrollmentCodeHeader: code}, nil); r.Code != http.StatusNotFound {
		t.Fatalf("bundle with a used code: %d %s", r.Code, r.Body.String())
	}
	view = f.machineView(id)
	if view["status"] != machineStatusPendingKey || view["enrollmentExpiresAt"] != nil || view["pendingPublicKeySha256"] != fingerprint.SHA256Hex(machine.ed25519Public()) {
		t.Fatalf("view after enroll: %v", view)
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/machines/"+id+"/enrollment", map[string]any{"expectedVersion": registryVersion(t, f), "reason": "again", "confirm": true}); r.Code != http.StatusConflict || problemCode(t, r) != "MACHINE_ALREADY_ENROLLED" {
		t.Fatalf("reissue for an enrolled machine: %d %s", r.Code, r.Body.String())
	}
	// 审计有 machine_enrolled，但里面没有令牌、令牌 sha256 和注册码
	var summary string
	if err := f.db.QueryRow(`SELECT summary FROM audit_events WHERE tenant_id=0 AND action='machine_enrolled' AND target_id=?`, id).Scan(&summary); err != nil {
		t.Fatalf("machine_enrolled audit: %v", err)
	}
	for _, secret := range []string{token, sha256Hex(token), code, sha256Hex(code)} {
		if strings.Contains(summary, secret) {
			t.Fatalf("the audit leaks a credential: %s", summary)
		}
	}
	// 平台管理员按视图里的指纹接受之后，令牌可用
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/machines/"+id+"/accept-key", map[string]any{
		"publicKeySha256": view["pendingPublicKeySha256"], "expectedVersion": registryVersion(t, f), "reason": "fingerprint shown by install.sh", "confirm": true,
	}); r.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", r.Code, r.Body.String())
	}
	if r := f.do(http.MethodPost, "/v1/build-agent/claim", token, nil, map[string]any{"platforms": []string{"android"}, "kinds": []string{"apk"}}); r.Code != http.StatusNoContent {
		t.Fatalf("an accepted enrolled builder: %d %s", r.Code, r.Body.String())
	}

	// 过期：把有效期改到过去
	expiring, expiringCode := f.createMachine(machineRoleBuilder, "builder-expire-"+uniqueSuffix(), nil)
	f.mutateRegistry(func(doc *buildMachinesDoc) {
		index, _ := doc.find(expiring)
		doc.Machines[index].Enrollment.ExpiresAt = iso(time.Now().UTC().Add(-time.Second))
	})
	if r := f.describe(expiringCode); r.Code != http.StatusNotFound || problemCode(t, r) != "ENROLLMENT_CODE_INVALID" {
		t.Fatalf("describe with an expired code: %d %s", r.Code, r.Body.String())
	}
	if r := f.enroll(expiringCode, nil, newGateMachine(t, machineRoleBuilder, "x").ed25519Public()); r.Code != http.StatusNotFound {
		t.Fatalf("enroll with an expired code: %d %s", r.Code, r.Body.String())
	}
	// 重发：新码可用，旧码作废
	reissued := f.adminDo(http.MethodPost, "/v1/admin/platform/machines/"+expiring+"/enrollment", map[string]any{"expectedVersion": registryVersion(t, f), "reason": "the code expired", "confirm": true})
	if reissued.Code != http.StatusOK {
		t.Fatalf("reissue: %d %s", reissued.Code, reissued.Body.String())
	}
	reissuedBody := decodeBody(t, reissued)
	newCode := reissuedBody["enrollment"].(map[string]any)["code"].(string)
	if newCode == expiringCode || reissuedBody["machine"].(map[string]any)["status"] != machineStatusPendingEnrollment {
		t.Fatalf("reissue response: %v", reissuedBody)
	}
	if r := f.describe(expiringCode); r.Code != http.StatusNotFound {
		t.Fatalf("the replaced code still works: %d", r.Code)
	}
	if r := f.describe(newCode); r.Code != http.StatusOK {
		t.Fatalf("the reissued code: %d %s", r.Code, r.Body.String())
	}
	if f.auditCount(platformTenantID, "build_machine_enrollment_reissue") < 1 {
		t.Fatal("the reissue was not audited")
	}
	// 吊销之后码作废，也不能再重发
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/machines/"+expiring+"/revoke", map[string]any{"expectedVersion": registryVersion(t, f), "reason": "not needed", "confirm": true}); r.Code != http.StatusOK {
		t.Fatalf("revoke a pending machine: %d %s", r.Code, r.Body.String())
	}
	if r := f.describe(newCode); r.Code != http.StatusNotFound {
		t.Fatalf("a revoked machine's code: %d", r.Code)
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/machines/"+expiring+"/enrollment", map[string]any{"expectedVersion": registryVersion(t, f), "reason": "again", "confirm": true}); r.Code != http.StatusConflict || problemCode(t, r) != "MACHINE_REVOKED" {
		t.Fatalf("reissue for a revoked machine: %d %s", r.Code, r.Body.String())
	}
}

// enroll 的公钥规则：构建机只有 Ed25519、签名闸两把都要、公钥不能与别的机器重复。失败不消耗注册码。
func TestDBEnrollmentValidatesTheReportedKeys(t *testing.T) {
	f := newGateFixture(t, 121)
	f.registerRecoveryKey("platform-recovery")
	_, builderCode := f.createMachine(machineRoleBuilder, "builder-keys-"+uniqueSuffix(), nil)
	signerID, signerCode := f.createMachine(machineRoleSigner, "signer-keys-"+uniqueSuffix(), signerRoleStandby)
	builder := newGateMachine(t, machineRoleBuilder, "b")
	signer := newGateMachine(t, machineRoleSigner, "s")
	if r := f.enroll(builderCode, signer.X25519.PublicKey().Bytes(), builder.ed25519Public()); r.Code != http.StatusBadRequest || problemCode(t, r) != "INVALID_MACHINE_KEY" {
		t.Fatalf("a builder with an X25519 key: %d %s", r.Code, r.Body.String())
	}
	if r := f.enroll(signerCode, nil, signer.ed25519Public()); r.Code != http.StatusBadRequest || problemCode(t, r) != "INVALID_MACHINE_KEY" {
		t.Fatalf("a signer without an X25519 key: %d %s", r.Code, r.Body.String())
	}
	if r := f.enroll(signerCode, f.primary.X25519.PublicKey().Bytes(), signer.ed25519Public()); r.Code != http.StatusConflict || problemCode(t, r) != "MACHINE_KEY_IN_USE" {
		t.Fatalf("a signer reusing the primary's key: %d %s", r.Code, r.Body.String())
	}
	if r := f.do(http.MethodPost, "/v1/machine-setup/enroll", "", nil, map[string]any{"code": signerCode, "x25519PublicKey": "not base64", "ed25519PublicKey": "x"}); r.Code != http.StatusBadRequest {
		t.Fatalf("malformed keys: %d %s", r.Code, r.Body.String())
	}
	// 上面的失败都没有消耗注册码
	token := f.enrolledToken(signerCode, signer)
	record := f.machineRecord(signerID)
	if record.Pending == nil || record.Pending.PublicKeySHA256 != signer.recipient() || string(record.Pending.Ed25519PublicKeySHA256) != fingerprint.SHA256Hex(signer.ed25519Public()) {
		t.Fatalf("signer pending keys: %+v", record.Pending)
	}
	if r := f.do(http.MethodGet, "/v1/signer/keystore-checks", token, nil, nil); r.Code != http.StatusForbidden || problemCode(t, r) != "MACHINE_KEY_NOT_ACCEPTED" {
		t.Fatalf("an enrolled signer before acceptance: %d %s", r.Code, r.Body.String())
	}
}

// 同一个注册码并发注册：恰好一个成功，其余 404；登记里挂的是赢家的公钥、存的是赢家令牌的 sha256。
func TestDBEnrollmentRaceHasExactlyOneWinner(t *testing.T) {
	f := newGateFixture(t, 122)
	id, code := f.createMachine(machineRoleBuilder, "builder-race-"+uniqueSuffix(), nil)
	const contenders = 8
	type outcome struct {
		status int
		body   []byte
		key    []byte
	}
	keys := make([][]byte, contenders)
	requests := make([]*http.Request, contenders)
	for i := range contenders {
		keys[i] = newGateMachine(t, machineRoleBuilder, "c").ed25519Public()
		raw, _ := json.Marshal(map[string]any{"code": code, "x25519PublicKey": nil, "ed25519PublicKey": base64.StdEncoding.EncodeToString(keys[i])})
		requests[i] = httptest.NewRequest(http.MethodPost, "/v1/machine-setup/enroll", bytes.NewReader(raw))
		requests[i].Header.Set("content-type", "application/json")
	}
	outcomes := make([]outcome, contenders)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range contenders {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			recorder := httptest.NewRecorder()
			f.router.ServeHTTP(recorder, requests[i])
			outcomes[i] = outcome{status: recorder.Code, body: recorder.Body.Bytes(), key: keys[i]}
		}(i)
	}
	close(start)
	wg.Wait()
	winners := 0
	var winner outcome
	for _, o := range outcomes {
		switch o.status {
		case http.StatusOK:
			winners++
			winner = o
		case http.StatusNotFound:
		default:
			t.Fatalf("an enrollment contender got %d %s", o.status, o.body)
		}
	}
	if winners != 1 {
		t.Fatalf("%d enrollments succeeded with one code", winners)
	}
	var result map[string]any
	_ = json.Unmarshal(winner.body, &result)
	record := f.machineRecord(id)
	if record.TokenSHA256 != sha256Hex(result["token"].(string)) || record.Pending == nil || record.Pending.PublicKeySHA256 != fingerprint.SHA256Hex(winner.key) {
		t.Fatalf("the registry does not hold the winner: %+v", record)
	}
	if f.auditCount(platformTenantID, "machine_enrolled") < 1 {
		t.Fatal("no machine_enrolled audit")
	}
	var audits int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=0 AND action='machine_enrolled' AND target_id=?`, id).Scan(&audits)
	if audits != 1 {
		t.Fatalf("machine_enrolled audited %d times", audits)
	}
}

// describe 与安装包：按角色给安装包清单；签名闸给未吊销的恢复公钥；备签名闸给当前主签名闸的公钥；
// 安装包只给注册码所属角色；目录不在是 503；按来源 IP 限速；install.sh 原样下发。
func TestDBMachineSetupDescribeBundleAndInstallScript(t *testing.T) {
	f := newGateFixture(t, 123)
	live := f.registerRecoveryKey("platform-recovery")
	revoked := f.registerRecoveryKey("old-recovery")
	snapshot, _ := readRecoveryKeys(t.Context(), f.db, false)
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/recovery-keys/"+revoked.ID+"/revoke", map[string]any{"expectedVersion": snapshot.Version, "reason": "rotated", "confirm": true}); r.Code != http.StatusOK {
		t.Fatalf("revoke recovery key: %d %s", r.Code, r.Body.String())
	}
	_, builderCode := f.createMachine(machineRoleBuilder, "builder-setup-"+uniqueSuffix(), nil)
	_, standbyCode := f.createMachine(machineRoleSigner, "signer-setup-"+uniqueSuffix(), signerRoleStandby)

	f.s.machineBundleDir = filepath.Join(t.TempDir(), "missing")
	if r := f.describe(builderCode); r.Code != http.StatusServiceUnavailable || problemCode(t, r) != "MACHINE_BUNDLE_UNAVAILABLE" {
		t.Fatalf("describe without bundles: %d %s", r.Code, r.Body.String())
	}
	archives := f.installBundles()

	builder := decodeBody(t, f.describe(builderCode))
	bundle := builder["bundle"].(map[string]any)
	if builder["role"] != machineRoleBuilder || builder["signerRole"] != nil || bundle["archive"] != "builder.tar.gz" || bundle["commit"] != "0123abcd" ||
		bundle["archiveSha256"] != sha256HexBytes(archives[machineRoleBuilder]) || len(builder["recoveryKeys"].([]any)) != 0 || builder["primarySigner"] != nil ||
		len(bundle["files"].([]any)) != 1 {
		t.Fatalf("builder description: %v", builder)
	}
	standby := decodeBody(t, f.describe(standbyCode))
	keys := standby["recoveryKeys"].([]any)
	primary, _ := standby["primarySigner"].(map[string]any)
	if standby["bundle"].(map[string]any)["archive"] != "signer.tar.gz" || len(standby["bundle"].(map[string]any)["files"].([]any)) != 2 || len(keys) != 1 || keys[0].(map[string]any)["x25519PublicKeySha256"] != live.SHA256 ||
		primary == nil || primary["machineId"] != f.primary.ID || primary["ed25519PublicKeySha256"] != fingerprint.SHA256Hex(f.primary.ed25519Public()) ||
		primary["x25519PublicKey"] != base64.StdEncoding.EncodeToString(f.primary.X25519.PublicKey().Bytes()) {
		t.Fatalf("standby description: %v", standby)
	}
	// 新建的主签名闸（先把现在的主降为备）拿不到"当前主签名闸"
	f.writeMachines(append([]buildMachine{f.builder.record(""), f.primary.record(signerRoleStandby), f.standby.record(signerRoleStandby)}, pendingMachines(f)...)...)
	_, primaryCode := f.createMachine(machineRoleSigner, "signer-primary-"+uniqueSuffix(), signerRolePrimary)
	if described := decodeBody(t, f.describe(primaryCode)); described["primarySigner"] != nil || described["signerRole"] != signerRolePrimary {
		t.Fatalf("primary description: %v", described)
	}

	download := func(archive, code string) *httptest.ResponseRecorder {
		headers := map[string]string{}
		if code != "" {
			headers[enrollmentCodeHeader] = code
		}
		return f.do(http.MethodGet, "/v1/machine-setup/bundle/"+archive, "", headers, nil)
	}
	if r := download("builder.tar.gz", builderCode); r.Code != http.StatusOK || !bytes.Equal(r.Body.Bytes(), archives[machineRoleBuilder]) ||
		r.Header().Get("x-content-sha256") != sha256HexBytes(archives[machineRoleBuilder]) {
		t.Fatalf("download the builder bundle: %d", r.Code)
	}
	if r := download("signer.tar.gz", builderCode); r.Code != http.StatusForbidden || problemCode(t, r) != "MACHINE_ROLE_FORBIDDEN" {
		t.Fatalf("a builder code downloading the signer bundle: %d %s", r.Code, r.Body.String())
	}
	if r := download("other.tar.gz", builderCode); r.Code != http.StatusNotFound || problemCode(t, r) != "MACHINE_BUNDLE_NOT_FOUND" {
		t.Fatalf("an unknown bundle: %d %s", r.Code, r.Body.String())
	}
	if r := download("builder.tar.gz", ""); r.Code != http.StatusNotFound || problemCode(t, r) != "ENROLLMENT_CODE_INVALID" {
		t.Fatalf("a download without a code: %d %s", r.Code, r.Body.String())
	}
	// 归档与清单对不上（大小不同）：不下发
	if err := os.WriteFile(filepath.Join(f.s.machineBundleDir, "builder.tar.gz"), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := download("builder.tar.gz", builderCode); r.Code != http.StatusServiceUnavailable || problemCode(t, r) != "MACHINE_BUNDLE_UNAVAILABLE" {
		t.Fatalf("a bundle that differs from its manifest: %d %s", r.Code, r.Body.String())
	}

	// 限速按来源 IP：同一个地址第 21 次 describe 是 429，别的地址不受影响
	describeFrom := func(address string) int {
		request := httptest.NewRequest(http.MethodPost, "/v1/machine-setup/describe", strings.NewReader(`{"code":"rne_x"}`))
		request.Header.Set("content-type", "application/json")
		request.RemoteAddr = address
		recorder := httptest.NewRecorder()
		f.router.ServeHTTP(recorder, request)
		return recorder.Code
	}
	for i := 0; i < machineSetupPerMinute; i++ {
		if code := describeFrom("198.51.100.7:4000"); code != http.StatusNotFound {
			t.Fatalf("describe #%d: %d", i, code)
		}
	}
	if code := describeFrom("198.51.100.7:4001"); code != http.StatusTooManyRequests {
		t.Fatalf("describe over the limit: %d", code)
	}
	if code := describeFrom("198.51.100.8:4000"); code != http.StatusNotFound {
		t.Fatalf("another address was throttled: %d", code)
	}

	script := f.do(http.MethodGet, "/v1/machine-setup/install.sh", "", nil, nil)
	if script.Code != http.StatusOK || !bytes.Equal(script.Body.Bytes(), machinesetup.InstallScript) || !strings.HasPrefix(script.Header().Get("Content-Type"), "text/x-shellscript") {
		t.Fatalf("install.sh: %d %q", script.Code, script.Header().Get("Content-Type"))
	}
}

// pendingMachines 是登记里夹具三台之外、还没注册的机器（重写登记时保留它们）。
func pendingMachines(f *gateFixture) []buildMachine {
	f.t.Helper()
	snapshot, err := readMachineRegistry(context.Background(), f.db, false)
	if err != nil {
		f.t.Fatal(err)
	}
	out := []buildMachine{}
	for _, m := range snapshot.Doc.Machines {
		if m.Status == machineStatusPendingEnrollment {
			out = append(out, m)
		}
	}
	return out
}

// 新建签名闸要求平台已登记恢复公钥；安装命令由服务端拼好，签名闸带恢复公钥占位。
func TestDBSignerCreationNeedsARecoveryKeyAndTheInstallCommandIsComposed(t *testing.T) {
	f := newGateFixture(t, 124)
	body := map[string]any{"role": "signer", "name": "signer-new-" + uniqueSuffix(), "signerRole": "standby", "expectedVersion": registryVersion(t, f), "reason": "add a signer", "confirm": true}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/machines", body); r.Code != http.StatusConflict || problemCode(t, r) != "RECOVERY_KEY_NOT_CONFIGURED" {
		t.Fatalf("a signer without a recovery key: %d %s", r.Code, r.Body.String())
	}
	f.registerRecoveryKey("platform-recovery")
	// 签名闸的机器名最多 22 个字符（系统用户 rn-signer-<机器名> 不超过 Linux 的 32 个字符）；构建机仍按 40 个
	tooLong := map[string]any{"role": "signer", "name": "s" + strings.Repeat("x", 22), "signerRole": "standby", "expectedVersion": registryVersion(t, f), "reason": "add a signer", "confirm": true}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/machines", tooLong); r.Code != http.StatusBadRequest || problemCode(t, r) != "INVALID_MACHINE" ||
		!strings.Contains(r.Body.String(), "at most 22 characters") || !strings.Contains(r.Body.String(), "rn-signer-") {
		t.Fatalf("a 23-character signer name: %d %s", r.Code, r.Body.String())
	}
	longest := map[string]any{"role": "signer", "name": "s" + strings.Repeat("y", 21), "signerRole": "standby", "expectedVersion": registryVersion(t, f), "reason": "add a signer", "confirm": true}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/machines", longest); r.Code != http.StatusCreated {
		t.Fatalf("a 22-character signer name: %d %s", r.Code, r.Body.String())
	}
	longBuilder := map[string]any{"role": "builder", "name": "b" + strings.Repeat("z", 39), "signerRole": nil, "expectedVersion": registryVersion(t, f), "reason": "add a builder", "confirm": true}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/machines", longBuilder); r.Code != http.StatusCreated {
		t.Fatalf("a 40-character builder name: %d %s", r.Code, r.Body.String())
	}
	body["expectedVersion"] = registryVersion(t, f)
	created := f.adminDo(http.MethodPost, "/v1/admin/platform/machines", body)
	if created.Code != http.StatusCreated {
		t.Fatalf("create a signer: %d %s", created.Code, created.Body.String())
	}
	enrollment := decodeBody(t, created)["enrollment"].(map[string]any)
	code := enrollment["code"].(string)
	want := "curl -fsSL http://example.com/v1/machine-setup/install.sh | sudo bash -s -- --server http://example.com --code " + code +
		" --recovery-sha256 <从密码管理器粘贴恢复公钥指纹>"
	if enrollment["installCommand"] != want || enrollment["expiresAt"] == nil {
		t.Fatalf("signer install command: %v", enrollment)
	}
	builder := f.adminDo(http.MethodPost, "/v1/admin/platform/machines", map[string]any{"role": "builder", "name": "builder-cmd-" + uniqueSuffix(), "signerRole": nil,
		"expectedVersion": registryVersion(t, f), "reason": "add a builder", "confirm": true})
	builderEnrollment := decodeBody(t, builder)["enrollment"].(map[string]any)
	if builderEnrollment["installCommand"] != "curl -fsSL http://example.com/v1/machine-setup/install.sh | sudo bash -s -- --server http://example.com --code "+builderEnrollment["code"].(string) {
		t.Fatalf("builder install command: %v", builderEnrollment)
	}
}

// 安装命令里的源：只有可信代理说的 X-Forwarded-Proto 才算；生产一律 https。
func TestExternalOriginTrustsOnlyTrustedProxies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	origin := func(cfg config.Config, remote, proto string) string {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/admin/platform/machines", nil)
		c.Request.Host = "api.example.com"
		c.Request.RemoteAddr = remote
		if proto != "" {
			c.Request.Header.Set("x-forwarded-proto", proto)
		}
		return (&server{cfg: cfg}).externalOrigin(c)
	}
	proxies := config.Config{TrustedProxies: []string{"10.0.0.0/8", "192.0.2.9"}}
	for _, tc := range []struct {
		cfg           config.Config
		remote, proto string
		want          string
	}{
		{proxies, "10.1.2.3:5000", "https", "https://api.example.com"},
		{proxies, "192.0.2.9:5000", "https", "https://api.example.com"},
		{proxies, "203.0.113.5:5000", "https", "http://api.example.com"},
		{config.Config{}, "10.1.2.3:5000", "https", "http://api.example.com"},
		{proxies, "10.1.2.3:5000", "", "http://api.example.com"},
		{config.Config{Environment: "production"}, "203.0.113.5:5000", "", "https://api.example.com"},
	} {
		if got := origin(tc.cfg, tc.remote, tc.proto); got != tc.want {
			t.Fatalf("remote %s proto %q proxies %v: %s, want %s", tc.remote, tc.proto, tc.cfg.TrustedProxies, got, tc.want)
		}
	}
}

// 线上 amos 的登记是手工流程写的：没有 enrollment、reportedTrust 等字段。新代码照常读、照常鉴权。
func TestDBRegistryWrittenBeforeAutomationStillWorks(t *testing.T) {
	f := newGateFixture(t, 125)
	legacy := func(m gateMachine, role string) map[string]any {
		entry := map[string]any{
			"id": m.ID, "role": m.Role, "signerRole": nil, "name": m.Name, "status": "active", "tokenSha256": sha256Hex(m.Token),
			"publicKey": nil, "publicKeySha256": nil, "ed25519PublicKey": nil, "ed25519PublicKeySha256": nil, "pending": nil,
			"acceptedBy": "admin", "acceptedAt": "2026-09-16T08:00:00.000Z", "createdBy": "admin", "createdAt": "2026-09-16T07:00:00.000Z",
			"revokedBy": nil, "revokedAt": nil, "revokeReason": nil,
		}
		if m.Role == machineRoleBuilder {
			entry["publicKey"], entry["publicKeySha256"] = base64.StdEncoding.EncodeToString(m.ed25519Public()), fingerprint.SHA256Hex(m.ed25519Public())
			return entry
		}
		entry["signerRole"], entry["reportedLocalRole"], entry["reportedLocalRoleAt"] = role, role, "2026-09-16T09:00:00.000Z"
		entry["publicKey"], entry["publicKeySha256"] = base64.StdEncoding.EncodeToString(m.X25519.PublicKey().Bytes()), m.recipient()
		entry["ed25519PublicKey"], entry["ed25519PublicKeySha256"] = base64.StdEncoding.EncodeToString(m.ed25519Public()), fingerprint.SHA256Hex(m.ed25519Public())
		return entry
	}
	raw, _ := json.Marshal(map[string]any{"machines": []any{legacy(f.builder, ""), legacy(f.primary, signerRolePrimary), legacy(f.standby, signerRoleStandby)}})
	if _, err := f.db.Exec(`UPDATE app_configs SET config_value=?,version=version+1 WHERE tenant_id=0 AND config_key=?`, raw, buildMachinesConfigKey); err != nil {
		t.Fatal(err)
	}
	if _, err := readMachineRegistry(t.Context(), f.db, false); err != nil {
		t.Fatalf("a registry without the automation fields: %v", err)
	}
	if item := f.checkItem(f.primary); item == nil || item["box"] == nil {
		t.Fatalf("the primary's keystore checks on a legacy registry: %v", item)
	}
	view := f.machineView(f.primary.ID)
	if view["status"] != machineStatusActive || view["enrollmentExpiresAt"] != nil || view["reportedTrust"] != nil || view["reportedTrustAt"] != nil {
		t.Fatalf("legacy machine view: %v", view)
	}
	// 老记录上第一次写（报本机信任）之后仍然合法
	f.reportCheck(f.primary, true, "ok")
	if view := f.machineView(f.primary.ID); view["reportedTrust"] == nil {
		t.Fatalf("trust was not recorded on a legacy entry: %v", view)
	}
}

// ---- 恢复公钥 ----

func TestDBRecoveryKeysRegisterListAndRevoke(t *testing.T) {
	f := newGateFixture(t, 126)
	private, _ := ecdh.X25519().GenerateKey(rand.Reader)
	file, _ := recovery.NewPublic("platform-recovery", private.PublicKey().Bytes(), time.Now().UTC())
	post := func(publicFile any, version int, confirm bool) *httptest.ResponseRecorder {
		return f.adminDo(http.MethodPost, "/v1/admin/platform/recovery-keys", map[string]any{"publicFile": publicFile, "expectedVersion": version, "reason": "register recovery", "confirm": confirm})
	}
	tampered := file
	tampered.X25519PublicKeySHA256 = strings.Repeat("0", 64)
	if r := post(tampered, 0, true); r.Code != http.StatusUnprocessableEntity || problemCode(t, r) != "RECOVERY_KEY_INVALID" {
		t.Fatalf("a public file whose sha256 does not match: %d %s", r.Code, r.Body.String())
	}
	if r := post(map[string]any{"format": recovery.PublicFormat, "surprise": 1}, 0, true); r.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a public file with unknown fields: %d %s", r.Code, r.Body.String())
	}
	if r := post(file, 0, false); r.Code != http.StatusBadRequest || problemCode(t, r) != "INVALID_RECOVERY_KEY" {
		t.Fatalf("without confirm: %d %s", r.Code, r.Body.String())
	}
	if r := post(file, 3, true); r.Code != http.StatusConflict || problemCode(t, r) != "RECOVERY_KEYS_VERSION_CONFLICT" {
		t.Fatalf("a stale version: %d %s", r.Code, r.Body.String())
	}
	created := post(file, 0, true)
	if created.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", created.Code, created.Body.String())
	}
	item := decodeBody(t, created)["item"].(map[string]any)
	if item["x25519PublicKeySha256"] != file.X25519PublicKeySHA256 || item["name"] != "platform-recovery" || item["revokedAt"] != nil || item["createdBy"] != "tester@example.com" {
		t.Fatalf("registered item: %v", item)
	}
	if r := post(file, 1, true); r.Code != http.StatusConflict || problemCode(t, r) != "RECOVERY_KEY_EXISTS" {
		t.Fatalf("registering the same key twice: %d %s", r.Code, r.Body.String())
	}
	list := decodeBody(t, f.adminDo(http.MethodGet, "/v1/admin/platform/recovery-keys", nil))
	if list["version"] != float64(1) || len(list["items"].([]any)) != 1 {
		t.Fatalf("list: %v", list)
	}
	revoke := func(id string, version int) *httptest.ResponseRecorder {
		return f.adminDo(http.MethodPost, "/v1/admin/platform/recovery-keys/"+id+"/revoke", map[string]any{"expectedVersion": version, "reason": "rotate the recovery key", "confirm": true})
	}
	if r := revoke("rck_unknownunknown", 1); r.Code != http.StatusNotFound || problemCode(t, r) != "RECOVERY_KEY_NOT_FOUND" {
		t.Fatalf("revoke an unknown key: %d %s", r.Code, r.Body.String())
	}
	revoked := revoke(item["id"].(string), 1)
	if revoked.Code != http.StatusOK || decodeBody(t, revoked)["item"].(map[string]any)["revokedAt"] == nil {
		t.Fatalf("revoke: %d %s", revoked.Code, revoked.Body.String())
	}
	if r := revoke(item["id"].(string), 2); r.Code != http.StatusConflict || problemCode(t, r) != "RECOVERY_KEY_ALREADY_REVOKED" {
		t.Fatalf("revoke twice: %d %s", r.Code, r.Body.String())
	}
	if r := post(file, 2, true); r.Code != http.StatusConflict || problemCode(t, r) != "RECOVERY_KEY_EXISTS" {
		t.Fatalf("re-registering a revoked key: %d %s", r.Code, r.Body.String())
	}
	if f.auditCount(platformTenantID, "build_recovery_key_create") < 1 || f.auditCount(platformTenantID, "build_recovery_key_revoke") < 1 {
		t.Fatal("recovery key changes were not audited")
	}
	// 只对平台管理员开放
	f.s.cfg.PlatformAdminUsernames = []string{"someone-else@example.com"}
	f.router = f.s.routes()
	if r := f.adminDo(http.MethodGet, "/v1/admin/platform/recovery-keys", nil); r.Code != http.StatusForbidden {
		t.Fatalf("a tenant admin listed recovery keys: %d", r.Code)
	}
}

// ---- 本机信任上报与 peers ----

// 签名闸报的本机信任列表只在变化时写（顺序不同算同一份），视图里带出来；形状不对 400。
func TestDBReportedTrustIsWrittenOnlyWhenItChanges(t *testing.T) {
	f := newGateFixture(t, 127)
	keystoreVersion, _ := f.keystoreVersions()
	item := map[string]any{"tenantSlug": f.slug, "keystoreVersion": keystoreVersion, "decrypt": "ok", "confirmed": true,
		"confirmedTrustRootsDigest": f.currentDigest(), "trialSign": "ok", "error": nil}
	report := func(trust any) *httptest.ResponseRecorder {
		return f.do(http.MethodPost, "/v1/signer/keystore-checks", f.standby.Token, nil, map[string]any{"localRole": "standby", "trust": trust, "items": []any{item}})
	}
	for name, trust := range map[string]any{
		"missing arrays":   map[string]any{"signers": []any{}},
		"bad sha":          map[string]any{"signers": []any{map[string]any{"name": "a-b", "x25519Sha256": "x", "ed25519Sha256": strings.Repeat("a", 64)}}, "builders": []any{}, "recoveryKeys": []string{}},
		"bad builder id":   map[string]any{"signers": []any{}, "builders": []any{map[string]any{"builderId": "nope", "ed25519Sha256": strings.Repeat("a", 64)}}, "recoveryKeys": []string{}},
		"bad recovery sha": map[string]any{"signers": []any{}, "builders": []any{}, "recoveryKeys": []string{"ABC"}},
		"unknown field":    map[string]any{"signers": []any{}, "builders": []any{}, "recoveryKeys": []string{}, "extra": 1},
	} {
		if r := report(trust); r.Code != http.StatusBadRequest || problemCode(t, r) != "INVALID_KEYSTORE_CHECK" {
			t.Fatalf("trust %s: %d %s", name, r.Code, r.Body.String())
		}
	}
	if r := f.do(http.MethodPost, "/v1/signer/keystore-checks", f.standby.Token, nil, map[string]any{"localRole": "standby", "items": []any{}}); r.Code != http.StatusBadRequest {
		t.Fatalf("a report without trust: %d %s", r.Code, r.Body.String())
	}
	trust := f.localTrust()
	version := registryVersion(t, f)
	if r := report(trust); r.Code != http.StatusNoContent {
		t.Fatalf("report: %d %s", r.Code, r.Body.String())
	}
	if after := registryVersion(t, f); after != version+1 {
		t.Fatalf("the first trust report must write once: %d -> %d", version, after)
	}
	view := f.machineView(f.standby.ID)
	reported, _ := view["reportedTrust"].(map[string]any)
	if reported == nil || len(reported["signers"].([]any)) != 2 || len(reported["builders"].([]any)) != 1 || view["reportedTrustAt"] == nil {
		t.Fatalf("view of the reported trust: %v", view)
	}
	// 顺序不同、内容相同：不写
	reordered := map[string]any{"signers": []any{trust["signers"].([]any)[1], trust["signers"].([]any)[0]}, "builders": trust["builders"], "recoveryKeys": []string{}}
	for i := 0; i < 3; i++ {
		if r := report(reordered); r.Code != http.StatusNoContent {
			t.Fatalf("repeat: %d %s", r.Code, r.Body.String())
		}
	}
	if after := registryVersion(t, f); after != version+1 {
		t.Fatalf("an unchanged trust list bumped the registry: %d -> %d", version+1, after)
	}
	// 本机新信任了一把恢复公钥：写一次、审计一次
	changed := map[string]any{"signers": trust["signers"], "builders": trust["builders"], "recoveryKeys": []string{strings.Repeat("c", 64)}}
	if r := report(changed); r.Code != http.StatusNoContent {
		t.Fatalf("report changed trust: %d %s", r.Code, r.Body.String())
	}
	if after := registryVersion(t, f); after != version+2 {
		t.Fatalf("a changed trust list must write once: %d", after)
	}
	var audits int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE tenant_id=0 AND action='build_machine_trust_report' AND target_id=?`, f.standby.ID).Scan(&audits)
	if audits != 2 {
		t.Fatalf("trust changes audited %d times, want 2", audits)
	}
}

// peers 只列 active 的机器与未吊销的恢复公钥；构建机令牌进不来。
func TestDBSignerPeersListOnlyActiveMachinesAndLiveRecoveryKeys(t *testing.T) {
	f := newGateFixture(t, 128)
	live := f.registerRecoveryKey("platform-recovery")
	old := f.registerRecoveryKey("old-recovery")
	snapshot, _ := readRecoveryKeys(t.Context(), f.db, false)
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/recovery-keys/"+old.ID+"/revoke", map[string]any{"expectedVersion": snapshot.Version, "reason": "rotated", "confirm": true}); r.Code != http.StatusOK {
		t.Fatalf("revoke: %d", r.Code)
	}
	f.createMachine(machineRoleBuilder, "builder-pending-"+uniqueSuffix(), nil)
	if r := f.do(http.MethodGet, "/v1/signer/peers", f.builder.Token, nil, nil); r.Code != http.StatusForbidden {
		t.Fatalf("a builder read peers: %d", r.Code)
	}
	r := f.do(http.MethodGet, "/v1/signer/peers", f.standby.Token, nil, nil)
	if r.Code != http.StatusOK {
		t.Fatalf("peers: %d %s", r.Code, r.Body.String())
	}
	body := decodeBody(t, r)
	signers, builders, keys := body["signers"].([]any), body["builders"].([]any), body["recoveryKeys"].([]any)
	if len(signers) != 2 || len(builders) != 1 || len(keys) != 1 {
		t.Fatalf("peers: %v", body)
	}
	for _, entry := range signers {
		signer := entry.(map[string]any)
		want := f.primary
		if signer["machineId"] == f.standby.ID {
			want = f.standby
		}
		if signer["x25519PublicKeySha256"] != want.recipient() || signer["ed25519PublicKey"] != base64.StdEncoding.EncodeToString(want.ed25519Public()) || signer["status"] != "active" {
			t.Fatalf("peer signer: %v", signer)
		}
	}
	if builder := builders[0].(map[string]any); builder["machineId"] != f.builder.ID || builder["publicKeySha256"] != fingerprint.SHA256Hex(f.builder.ed25519Public()) {
		t.Fatalf("peer builder: %v", builder)
	}
	if key := keys[0].(map[string]any); key["x25519PublicKeySha256"] != live.SHA256 || key["revoked"] != false {
		t.Fatalf("peer recovery key: %v", key)
	}
}

// ---- 生成签名密钥 ----

// 发起：前提（恢复公钥、主签名闸、包名、版本）逐条检查；只有一条未完成的请求；只下发给主签名闸；
// 已有可用密钥的租户在换密钥期间仍然就绪。交回：只收路由主签名闸本人、签名有效、按请求的包名与别名、
// 含恢复收件人的密钥；同一事务写密钥、发布身份与请求状态；重试幂等；之后备签名闸拿到生成者与签名。
func TestDBKeystoreGenerationHappyPathAndStateMachine(t *testing.T) {
	f := newGateFixture(t, 129)
	if r := f.generate(f.generateBody(f.packageName)); r.Code != http.StatusConflict || problemCode(t, r) != "RECOVERY_KEY_NOT_CONFIGURED" {
		t.Fatalf("generate without a recovery key: %d %s", r.Code, r.Body.String())
	}
	recoveryKey := f.registerRecoveryKey("platform-recovery")
	for name, mutate := range map[string]func(map[string]any){
		"no confirm":      func(b map[string]any) { b["confirm"] = false },
		"short reason":    func(b map[string]any) { b["reason"] = "x" },
		"upper package":   func(b map[string]any) { b["packageName"] = "Com.Example.App" },
		"no version":      func(b map[string]any) { delete(b, "expectedVersion") },
		"unknown field":   func(b map[string]any) { b["alias"] = "mine" },
		"negative ident.": func(b map[string]any) { b["releaseIdentityExpectedVersion"] = -1 },
	} {
		body := f.generateBody(f.packageName)
		mutate(body)
		if r := f.generate(body); r.Code != http.StatusBadRequest || problemCode(t, r) != "INVALID_BUILD_KEYSTORE_GENERATION" {
			t.Fatalf("%s: %d %s", name, r.Code, r.Body.String())
		}
	}
	if r := f.generate(f.generateBody("com.other.app")); r.Code != http.StatusUnprocessableEntity || problemCode(t, r) != "KEYSTORE_PACKAGE_MISMATCH" {
		t.Fatalf("generate for another package: %d %s", r.Code, r.Body.String())
	}
	stale := f.generateBody(f.packageName)
	stale["expectedVersion"] = stale["expectedVersion"].(int) - 1
	if r := f.generate(stale); r.Code != http.StatusConflict || problemCode(t, r) != "STALE_BUILD_KEYSTORE" {
		t.Fatalf("a stale keystore version: %d %s", r.Code, r.Body.String())
	}
	stale = f.generateBody(f.packageName)
	stale["releaseIdentityExpectedVersion"] = stale["releaseIdentityExpectedVersion"].(int) + 1
	if r := f.generate(stale); r.Code != http.StatusConflict || problemCode(t, r) != "STALE_RELEASE_IDENTITY" {
		t.Fatalf("a stale identity version: %d %s", r.Code, r.Body.String())
	}
	f.writeMachines(f.builder.record(""), f.primary.record(signerRoleStandby), f.standby.record(signerRoleStandby))
	if r := f.generate(f.generateBody(f.packageName)); r.Code != http.StatusConflict || problemCode(t, r) != "PRIMARY_SIGNER_MISSING" {
		t.Fatalf("generate without a primary: %d %s", r.Code, r.Body.String())
	}
	f.writeMachines(f.builder.record(""), f.primary.record(signerRolePrimary), f.standby.record(signerRoleStandby))

	keystoreVersion, identityVersion := f.keystoreVersions()
	accepted := f.generate(f.generateBody(f.packageName))
	if accepted.Code != http.StatusAccepted {
		t.Fatalf("generate: %d %s", accepted.Code, accepted.Body.String())
	}
	view := decodeBody(t, accepted)["generationRequest"].(map[string]any)
	requestID := view["requestId"].(string)
	alias := defaultGenerationAlias(f.slug)
	if view["status"] != generationPending || view["packageName"] != f.packageName || view["alias"] != alias || view["error"] != nil || view["completedAt"] != nil ||
		!keystorebox.ValidGenerationRequestID(requestID) || !strings.HasPrefix(requestID, "kgr_") {
		t.Fatalf("generation request view: %v", view)
	}
	if r := f.generate(f.generateBody(f.packageName)); r.Code != http.StatusConflict || problemCode(t, r) != "KEYSTORE_GENERATION_IN_PROGRESS" {
		t.Fatalf("a second pending generation: %d %s", r.Code, r.Body.String())
	}
	if f.auditCount(f.tenant, "build_keystore_generation_request") != 1 {
		t.Fatal("the generation request was not audited")
	}
	// 已有可用密钥：换密钥期间照常就绪，生成状态在视图里
	if codes := readinessCodes(t, f); len(codes) != 0 {
		t.Fatalf("a configured tenant became unready while a key is generated: %v", codes)
	}
	if got := f.keystoreView()["generationRequest"].(map[string]any); got["requestId"] != requestID || got["status"] != generationPending {
		t.Fatalf("keystore view generation request: %v", got)
	}

	// 只有主签名闸拿到生成请求，带着首次信任用的信任根
	primaryItem := f.checkItem(f.primary)
	generation, _ := primaryItem["generationRequest"].(map[string]any)
	if generation == nil || generation["requestId"] != requestID || generation["packageName"] != f.packageName || generation["alias"] != alias ||
		generation["trustRootsDigest"] != f.currentDigest() || generation["publishedMaxBuildNumber"] != float64(0) || primaryItem["box"] == nil ||
		primaryItem["generator"] != nil || primaryItem["upload"] != nil {
		t.Fatalf("primary check item: %v", primaryItem)
	}
	if standbyItem := f.checkItem(f.standby); standbyItem["generationRequest"] != nil {
		t.Fatalf("the standby got the generation request: %v", standbyItem)
	}

	certificate := newCertificateSHA256()
	recipients := [][]byte{f.primary.X25519.PublicKey().Bytes(), f.standby.X25519.PublicKey().Bytes(), recoveryKey.Private.PublicKey().Bytes()}
	upload := f.sealedUpload(f.slug, f.packageName, alias, certificate, recipients...)
	// 备签名闸交不回来；主签名闸冒充备签名闸也不行；签名不是主签名闸登记的钥签的也不行
	if r := f.deliver(f.standby, requestID, upload, f.standby.ID, f.standby.Ed25519); r.Code != http.StatusForbidden || problemCode(t, r) != "KEYSTORE_GENERATOR_NOT_PRIMARY" {
		t.Fatalf("delivery by the standby: %d %s", r.Code, r.Body.String())
	}
	if r := f.deliver(f.primary, requestID, upload, f.standby.ID, f.primary.Ed25519); r.Code != http.StatusForbidden || problemCode(t, r) != "KEYSTORE_GENERATOR_NOT_PRIMARY" {
		t.Fatalf("the primary naming the standby as generator: %d %s", r.Code, r.Body.String())
	}
	if r := f.deliver(f.primary, requestID, upload, f.primary.ID, f.standby.Ed25519); r.Code != http.StatusUnprocessableEntity || problemCode(t, r) != "KEYSTORE_GENERATION_SIGNATURE_INVALID" {
		t.Fatalf("a signature by another key: %d %s", r.Code, r.Body.String())
	}
	otherSignature, _ := keystorebox.SignGeneration(f.primary.Ed25519, "kgr_another_request", upload)
	if r := f.deliverSigned(f.primary, requestID, upload, f.primary.ID, otherSignature); r.Code != http.StatusUnprocessableEntity || problemCode(t, r) != "KEYSTORE_GENERATION_SIGNATURE_INVALID" {
		t.Fatalf("a signature over another request: %d %s", r.Code, r.Body.String())
	}
	wrongAlias := f.sealedUpload(f.slug, f.packageName, "release", certificate, recipients...)
	if r := f.deliver(f.primary, requestID, wrongAlias, f.primary.ID, f.primary.Ed25519); r.Code != http.StatusUnprocessableEntity || problemCode(t, r) != "BUILD_KEYSTORE_IDENTITY_MISMATCH" {
		t.Fatalf("a key with another alias: %d %s", r.Code, r.Body.String())
	}
	if got := f.storedGenerationRequest(); got.Status != generationPending {
		t.Fatalf("a refused delivery changed the request: %+v", got)
	}

	delivered := f.deliver(f.primary, requestID, upload, f.primary.ID, f.primary.Ed25519)
	if delivered.Code != http.StatusOK {
		t.Fatalf("deliver: %d %s", delivered.Code, delivered.Body.String())
	}
	versions := decodeBody(t, delivered)
	if versions["keystoreVersion"] != float64(keystoreVersion+1) || versions["releaseIdentityVersion"] != float64(identityVersion+1) {
		t.Fatalf("delivery versions: %v (before %d/%d)", versions, keystoreVersion, identityVersion)
	}
	// 重试（签名闸没收到响应）：同样的结果，不再写
	if retry := f.deliver(f.primary, requestID, upload, f.primary.ID, f.primary.Ed25519); retry.Code != http.StatusOK || decodeBody(t, retry)["keystoreVersion"] != versions["keystoreVersion"] {
		t.Fatalf("retry: %d %s", retry.Code, retry.Body.String())
	}
	state, err := f.s.buildKeystoreStateFor(t.Context(), f.db, f.tenant)
	if err != nil || !state.configured() || state.Record.CertificateSHA256 != certificate || state.Record.Generator == nil ||
		state.Record.Generator.MachineID != f.primary.ID || state.Record.GenerationRequestID != requestID || state.Version != keystoreVersion+1 {
		t.Fatalf("stored keystore: %v %+v", err, state.Record)
	}
	identity, _ := f.s.androidReleaseIdentityRecord(t.Context(), f.tenant)
	if identity == nil || identity.Value.SignerSHA256 != certificate || identity.Value.PackageName != f.packageName {
		t.Fatalf("release identity after delivery: %+v", identity)
	}
	if got := f.storedGenerationRequest(); got.Status != generationDone || got.CompletedAt == "" {
		t.Fatalf("request after delivery: %+v", got)
	}
	if f.auditCount(f.tenant, "build_keystore_generated") != 1 {
		t.Fatal("build_keystore_generated audited not exactly once")
	}
	// 新密钥：主签名闸不再拿到生成请求；备签名闸拿到生成者、签名、请求 id 与完整上传文件
	if item := f.checkItem(f.primary); item["generationRequest"] != nil {
		t.Fatalf("a done request is still delivered: %v", item)
	}
	standbyItem := f.checkItem(f.standby)
	generator, _ := standbyItem["generator"].(map[string]any)
	uploadJSON, _ := json.Marshal(standbyItem["upload"])
	var echoed keystorebox.Upload
	_ = json.Unmarshal(uploadJSON, &echoed)
	if generator == nil || generator["machineId"] != f.primary.ID || generator["ed25519PublicKeySha256"] != fingerprint.SHA256Hex(f.primary.ed25519Public()) ||
		standbyItem["generationRequestId"] != requestID || standbyItem["keystoreVersion"] != float64(keystoreVersion+1) ||
		keystorebox.VerifyGeneration(f.primary.Ed25519.Public().(ed25519.PublicKey), requestID, echoed, standbyItem["generationSignature"].(string)) != nil {
		t.Fatalf("standby check item: %v", standbyItem)
	}
	keystore := f.keystoreView()
	recoveryRecipients := keystore["recoveryRecipients"].([]any)
	if keystore["generator"].(map[string]any)["name"] != f.primary.Name || len(recoveryRecipients) != 1 || recoveryRecipients[0] != recoveryKey.SHA256 ||
		keystore["generationRequest"].(map[string]any)["status"] != generationDone {
		t.Fatalf("keystore view after delivery: %v", keystore)
	}
	// 新密钥还没有被主签名闸检查：不是生成相关的原因
	if codes := readinessCodes(t, f); strings.Join(codes, ",") != readinessPrimaryCheckMissing {
		t.Fatalf("readiness after a generated key: %v", codes)
	}
	// 完成之后可以再发起
	if r := f.generate(f.generateBody(f.packageName)); r.Code != http.StatusAccepted {
		t.Fatalf("generate again after done: %d %s", r.Code, r.Body.String())
	}
}

// 交回的密钥按导入的全部规则校验，并且至少要有一把登记的、未吊销的恢复公钥；这些拒绝都不改变请求状态。
func TestDBGeneratedKeysNeedARecoveryRecipientAndKnownRecipients(t *testing.T) {
	f := newGateFixture(t, 130)
	recoveryKey := f.registerRecoveryKey("platform-recovery")
	revoked := f.registerRecoveryKey("revoked-recovery")
	snapshot, _ := readRecoveryKeys(t.Context(), f.db, false)
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/recovery-keys/"+revoked.ID+"/revoke", map[string]any{"expectedVersion": snapshot.Version, "reason": "rotated", "confirm": true}); r.Code != http.StatusOK {
		t.Fatalf("revoke: %d", r.Code)
	}
	accepted := f.generate(f.generateBody(f.packageName))
	if accepted.Code != http.StatusAccepted {
		t.Fatalf("generate: %d %s", accepted.Code, accepted.Body.String())
	}
	requestID := decodeBody(t, accepted)["generationRequest"].(map[string]any)["requestId"].(string)
	alias := defaultGenerationAlias(f.slug)
	primaryX, standbyX := f.primary.X25519.PublicKey().Bytes(), f.standby.X25519.PublicKey().Bytes()
	stranger, _ := ecdh.X25519().GenerateKey(rand.Reader)
	for name, tc := range map[string]struct {
		upload keystorebox.Upload
		code   string
	}{
		"signers only": {f.sealedUpload(f.slug, f.packageName, alias, newCertificateSHA256(), primaryX, standbyX), "KEYSTORE_RECOVERY_RECIPIENT_MISSING"},
		// 没有发给主签名闸自己的密文：收下的话发布身份换成新证书，而主签名闸再也拿不到这个租户
		"not sealed to the primary": {f.sealedUpload(f.slug, f.packageName, alias, newCertificateSHA256(), standbyX, recoveryKey.Private.PublicKey().Bytes()), "KEYSTORE_PRIMARY_RECIPIENT_MISSING"},
		"recovery key only":         {f.sealedUpload(f.slug, f.packageName, alias, newCertificateSHA256(), recoveryKey.Private.PublicKey().Bytes()), "KEYSTORE_PRIMARY_RECIPIENT_MISSING"},
		"revoked recovery key":      {f.sealedUpload(f.slug, f.packageName, alias, newCertificateSHA256(), primaryX, revoked.Private.PublicKey().Bytes()), "BUILD_KEYSTORE_RECIPIENT_UNKNOWN"},
		"unregistered recipient":    {f.sealedUpload(f.slug, f.packageName, alias, newCertificateSHA256(), primaryX, recoveryKey.Private.PublicKey().Bytes(), stranger.PublicKey().Bytes()), "BUILD_KEYSTORE_RECIPIENT_UNKNOWN"},
		"another tenant":            {f.sealedUpload("other-tenant", f.packageName, alias, newCertificateSHA256(), primaryX, recoveryKey.Private.PublicKey().Bytes()), "BUILD_KEYSTORE_TENANT_MISMATCH"},
		"another package":           {f.sealedUpload(f.slug, "com.other.app", alias, newCertificateSHA256(), primaryX, recoveryKey.Private.PublicKey().Bytes()), "BUILD_KEYSTORE_IDENTITY_MISMATCH"},
		"retired certificate":       {f.sealedUpload(f.slug, f.packageName, alias, "1a5d9fb446e2f4c8e1aa464a02b14248a265ea9c554f83eb01ec94886329e694", primaryX, recoveryKey.Private.PublicKey().Bytes()), "RELEASE_SIGNER_RETIRED"},
		"public debug certificate":  {f.sealedUpload(f.slug, f.packageName, alias, reactNativeDebugSignerSHA256, primaryX, recoveryKey.Private.PublicKey().Bytes()), "INVALID_RELEASE_IDENTITY"},
	} {
		if r := f.deliver(f.primary, requestID, tc.upload, f.primary.ID, f.primary.Ed25519); r.Code != http.StatusUnprocessableEntity || problemCode(t, r) != tc.code {
			t.Fatalf("%s: %d %s", name, r.Code, r.Body.String())
		}
	}
	if r := f.do(http.MethodPost, "/v1/signer/keystore-generations/"+requestID, f.primary.Token, nil, map[string]any{
		"upload": map[string]any{"format": "rn-android-keystore-upload/v2"}, "generator": map[string]any{"machineId": f.primary.ID, "ed25519PublicKeySha256": strings.Repeat("a", 64)}, "signature": "eA==",
	}); r.Code != http.StatusUnprocessableEntity || problemCode(t, r) != "BUILD_KEYSTORE_FORMAT_UNSUPPORTED" {
		t.Fatalf("a v2 upload: %d %s", r.Code, r.Body.String())
	}
	if r := f.do(http.MethodPost, "/v1/signer/keystore-generations/"+requestID, f.builder.Token, nil, map[string]any{}); r.Code != http.StatusForbidden || problemCode(t, r) != "MACHINE_ROLE_FORBIDDEN" {
		t.Fatalf("a builder token: %d %s", r.Code, r.Body.String())
	}
	if got := f.storedGenerationRequest(); got.Status != generationPending {
		t.Fatalf("refused deliveries changed the request: %+v", got)
	}
	if state, _ := f.s.buildKeystoreStateFor(t.Context(), f.db, f.tenant); state.Record.Generator != nil {
		t.Fatalf("a refused delivery replaced the keystore: %+v", state.Record)
	}
	// 至少一把恢复公钥、加上主签名闸自己即可，不要求加密给备签名闸
	if r := f.deliver(f.primary, requestID, f.sealedUpload(f.slug, f.packageName, alias, newCertificateSHA256(), primaryX, recoveryKey.Private.PublicKey().Bytes()), f.primary.ID, f.primary.Ed25519); r.Code != http.StatusOK {
		t.Fatalf("a key sealed to the primary and the recovery key: %d %s", r.Code, r.Body.String())
	}
}

// 发起之后签名密钥或发布身份被改过：请求按"过期"算（不再下发、不挡新的请求），交回 409 并落成 failed；
// 签名闸报失败：请求标 failed、带上原因，重复报 409。
func TestDBKeystoreGenerationGoesStaleAndCanFail(t *testing.T) {
	f := newGateFixture(t, 131)
	recoveryKey := f.registerRecoveryKey("platform-recovery")
	alias := defaultGenerationAlias(f.slug)
	first := f.generate(f.generateBody(f.packageName))
	if first.Code != http.StatusAccepted {
		t.Fatalf("generate: %d %s", first.Code, first.Body.String())
	}
	staleID := decodeBody(t, first)["generationRequest"].(map[string]any)["requestId"].(string)
	// 导入了一份密钥：版本变了
	f.uploadKeystore(f.primary, f.standby)
	if got := f.keystoreView()["generationRequest"].(map[string]any); got["status"] != generationFailed || got["error"].(map[string]any)["code"] != generationStaleCode {
		t.Fatalf("a request overtaken by an import: %v", got)
	}
	if item := f.checkItem(f.primary); item["generationRequest"] != nil {
		t.Fatalf("a stale request is still delivered: %v", item)
	}
	upload := f.sealedUpload(f.slug, f.packageName, alias, newCertificateSHA256(), f.primary.X25519.PublicKey().Bytes(), recoveryKey.Private.PublicKey().Bytes())
	if r := f.deliver(f.primary, staleID, upload, f.primary.ID, f.primary.Ed25519); r.Code != http.StatusConflict || problemCode(t, r) != generationStaleCode {
		t.Fatalf("delivering a stale request: %d %s", r.Code, r.Body.String())
	}
	if got := f.storedGenerationRequest(); got.Status != generationFailed || got.Error == nil || got.Error.Code != generationStaleCode {
		t.Fatalf("a stale delivery must be recorded as failed: %+v", got)
	}
	if f.auditCount(f.tenant, "build_keystore_generation_failed") != 1 {
		t.Fatal("the stale request was not audited as failed")
	}
	// 过期的请求不挡新的；旧请求 id 交回 409（不是当前请求）
	second := f.generate(f.generateBody(f.packageName))
	if second.Code != http.StatusAccepted {
		t.Fatalf("generate after a stale request: %d %s", second.Code, second.Body.String())
	}
	requestID := decodeBody(t, second)["generationRequest"].(map[string]any)["requestId"].(string)
	if r := f.deliver(f.primary, staleID, upload, f.primary.ID, f.primary.Ed25519); r.Code != http.StatusConflict || problemCode(t, r) != generationStaleCode {
		t.Fatalf("delivering a replaced request: %d %s", r.Code, r.Body.String())
	}
	// 发布身份被改（同值重存也加版本）：同样过期
	identity, _ := f.s.androidReleaseIdentityRecord(t.Context(), f.tenant)
	c, recorder := testContext(t, f.tenant, http.MethodPut, "/v1/admin/release-identity/android", map[string]any{
		"packageName": identity.Value.PackageName, "signerSha256": identity.Value.SignerSHA256, "expectedVersion": identity.Version, "reason": "save again", "confirm": true,
	})
	f.s.updateAndroidReleaseIdentity(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("save the identity: %d %s", recorder.Code, recorder.Body.String())
	}
	if r := f.deliver(f.primary, requestID, upload, f.primary.ID, f.primary.Ed25519); r.Code != http.StatusConflict || problemCode(t, r) != generationStaleCode {
		t.Fatalf("delivering after an identity change: %d %s", r.Code, r.Body.String())
	}

	third := f.generate(f.generateBody(f.packageName))
	if third.Code != http.StatusAccepted {
		t.Fatalf("generate: %d %s", third.Code, third.Body.String())
	}
	failID := decodeBody(t, third)["generationRequest"].(map[string]any)["requestId"].(string)
	fail := func(machine gateMachine, id string, body map[string]any) *httptest.ResponseRecorder {
		return f.do(http.MethodPost, "/v1/signer/keystore-generations/"+id+"/fail", machine.Token, nil, body)
	}
	if r := fail(f.primary, failID, map[string]any{"code": "trust roots changed", "detail": "x"}); r.Code != http.StatusBadRequest {
		t.Fatalf("a malformed failure code: %d %s", r.Code, r.Body.String())
	}
	if r := fail(f.standby, failID, map[string]any{"code": "NOT_LOCAL_PRIMARY", "detail": "x"}); r.Code != http.StatusForbidden || problemCode(t, r) != "KEYSTORE_GENERATOR_NOT_PRIMARY" {
		t.Fatalf("a failure reported by the standby: %d %s", r.Code, r.Body.String())
	}
	if r := fail(f.primary, failID, map[string]any{"code": "TRUST_ROOTS_CHANGED", "detail": "confirm first\x1b[2J"}); r.Code != http.StatusNoContent {
		t.Fatalf("report a failure: %d %s", r.Code, r.Body.String())
	}
	if r := fail(f.primary, failID, map[string]any{"code": "TRUST_ROOTS_CHANGED", "detail": "again"}); r.Code != http.StatusConflict || problemCode(t, r) != generationStaleCode {
		t.Fatalf("report a failure twice: %d %s", r.Code, r.Body.String())
	}
	got := f.keystoreView()["generationRequest"].(map[string]any)
	if failure, _ := got["error"].(map[string]any); got["status"] != generationFailed || failure["code"] != "TRUST_ROOTS_CHANGED" || failure["detail"] != "confirm first[2J" || got["completedAt"] == nil {
		t.Fatalf("a failed request: %v", got)
	}
	// 已有可用密钥：失败不影响就绪
	f.reportCheck(f.primary, true, "ok")
	if codes := readinessCodes(t, f); len(codes) != 0 {
		t.Fatalf("a failed regeneration made a configured tenant unready: %v", codes)
	}
	// 请求记录被写坏：不挡已有密钥的检查与就绪，发起新请求时覆盖它
	if _, err := f.db.Exec(`UPDATE app_configs SET config_value=JSON_SET(config_value,'$.status','exploded'),version=version+1 WHERE tenant_id=? AND config_key=?`, f.tenant, buildKeystoreRequestConfigKey); err != nil {
		t.Fatal(err)
	}
	if item := f.checkItem(f.primary); item == nil || item["box"] == nil {
		t.Fatalf("an unreadable request hid the tenant's keystore: %v", item)
	}
	if codes := readinessCodes(t, f); len(codes) != 0 || f.keystoreView()["generationRequest"] != nil {
		t.Fatalf("an unreadable request affected readiness: %v", codes)
	}
	if r := f.generate(f.generateBody(f.packageName)); r.Code != http.StatusAccepted {
		t.Fatalf("generate over an unreadable request: %d %s", r.Code, r.Body.String())
	}
}

// 新租户第一次生成：还没有 release.android 时包名取请求里的，信任根照样算得出来（与之后登记了身份时同一个摘要），
// 下发给主签名闸的项没有密文；交回时一并写入发布身份。
func TestDBFirstKeyGenerationForATenantWithoutReleaseIdentity(t *testing.T) {
	f := newGateFixture(t, 132)
	recoveryKey := f.registerRecoveryKey("platform-recovery")
	digest := f.currentDigest()
	if _, err := f.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key IN (?,?,?)`, f.tenant, buildKeystoreConfigKey, releaseAndroidIdentityConfigKey, buildKeystoreCheckConfigKey); err != nil {
		t.Fatal(err)
	}
	if r := f.generate(map[string]any{"packageName": f.packageName, "expectedVersion": 0, "releaseIdentityExpectedVersion": 0, "reason": "first key", "confirm": true}); r.Code != http.StatusAccepted {
		t.Fatalf("first generate: %d %s", r.Code, r.Body.String())
	}
	request := f.storedGenerationRequest()
	if codes := readinessCodes(t, f); !containsString(codes, readinessKeystoreNotConfigured) || !containsString(codes, readinessGenerationPending) || containsString(codes, readinessRecoveryKeyMissing) {
		t.Fatalf("readiness of a tenant waiting for its first key: %v", codes)
	}
	item := f.checkItem(f.primary)
	generation, _ := item["generationRequest"].(map[string]any)
	if item == nil || item["box"] != nil || item["packageName"] != nil || item["certificateSha256"] != nil || item["keystoreVersion"] != float64(0) ||
		generation == nil || generation["trustRootsDigest"] != digest || item["trustRootsDigest"] != digest {
		t.Fatalf("the first-generation item: %v", item)
	}
	if standby := f.checkItem(f.standby); standby != nil {
		t.Fatalf("the standby got an item for a tenant without a key: %v", standby)
	}
	// 主签名闸对没有密文的项报"检查结论"不会被收下
	if r := f.do(http.MethodPost, "/v1/signer/keystore-checks", f.primary.Token, nil, map[string]any{"localRole": "primary", "trust": f.localTrust(),
		"items": []any{map[string]any{"tenantSlug": f.slug, "keystoreVersion": 1, "decrypt": "failed", "confirmed": false, "confirmedTrustRootsDigest": nil, "trialSign": "pending", "error": "no box"}}}); r.Code != http.StatusNoContent {
		t.Fatalf("report: %d %s", r.Code, r.Body.String())
	}
	certificate := newCertificateSHA256()
	upload := f.sealedUpload(f.slug, f.packageName, request.Alias, certificate, f.primary.X25519.PublicKey().Bytes(), f.standby.X25519.PublicKey().Bytes(), recoveryKey.Private.PublicKey().Bytes())
	delivered := f.deliver(f.primary, request.RequestID, upload, f.primary.ID, f.primary.Ed25519)
	if delivered.Code != http.StatusOK {
		t.Fatalf("deliver the first key: %d %s", delivered.Code, delivered.Body.String())
	}
	if versions := decodeBody(t, delivered); versions["keystoreVersion"] != float64(1) || versions["releaseIdentityVersion"] != float64(1) {
		t.Fatalf("first key versions: %v", versions)
	}
	identity, _ := f.s.androidReleaseIdentityRecord(t.Context(), f.tenant)
	if identity == nil || identity.Value.PackageName != f.packageName || identity.Value.SignerSHA256 != certificate {
		t.Fatalf("release identity written with the first key: %+v", identity)
	}
	if got := f.currentDigest(); got != digest {
		t.Fatalf("the trust roots digest changed once the identity exists: %s vs %s", got, digest)
	}
	if codes := readinessCodes(t, f); strings.Join(codes, ",") != readinessPrimaryCheckMissing {
		t.Fatalf("readiness after the first key: %v", codes)
	}
	checks, _ := f.s.keystoreChecksFor(t.Context(), f.db, f.tenant)
	if len(checks) != 0 {
		t.Fatalf("a report for an item without a box was stored: %v", checks)
	}
}

// 主签名闸离线、或者一直算不出信任根时，请求不能永远挂着：超过 30 分钟（服务端时钟）读的时候就按
// KEYSTORE_GENERATION_TIMED_OUT 失败——不再下发、不挡新的请求、控制台与就绪这样显示；超时之后才到的
// 交回与失败报告按"请求不再 pending"409，并把超时写回库、审计一次。
func TestDBKeystoreGenerationTimesOut(t *testing.T) {
	f := newGateFixture(t, 134)
	recoveryKey := f.registerRecoveryKey("platform-recovery")
	base := time.Now().UTC()
	now := base
	f.s.clock = func() time.Time { return now }
	alias := defaultGenerationAlias(f.slug)
	requestAt := func() string {
		t.Helper()
		r := f.generate(f.generateBody(f.packageName))
		if r.Code != http.StatusAccepted {
			t.Fatalf("generate at %s: %d %s", now, r.Code, r.Body.String())
		}
		return decodeBody(t, r)["generationRequest"].(map[string]any)["requestId"].(string)
	}
	first := requestAt()
	if stored := f.storedGenerationRequest(); stored.RequestedAt != iso(base) {
		t.Fatalf("requestedAt does not come from the server clock: %+v", stored)
	}

	// 还没到 30 分钟：照常挂着、照常下发、再点生成 409
	now = base.Add(generationTimeout - time.Minute)
	if got := f.keystoreView()["generationRequest"].(map[string]any); got["status"] != generationPending {
		t.Fatalf("a request within the timeout: %v", got)
	}
	if item := f.checkItem(f.primary); item["generationRequest"] == nil {
		t.Fatalf("a request within the timeout is not delivered: %v", item)
	}
	if r := f.generate(f.generateBody(f.packageName)); r.Code != http.StatusConflict || problemCode(t, r) != "KEYSTORE_GENERATION_IN_PROGRESS" {
		t.Fatalf("generate while a request is pending: %d %s", r.Code, r.Body.String())
	}

	// 过了 30 分钟：读的时候就是失败（库里不改），不下发
	now = base.Add(generationTimeout + time.Minute)
	got := f.keystoreView()["generationRequest"].(map[string]any)
	if failure, _ := got["error"].(map[string]any); got["status"] != generationFailed || failure["code"] != generationTimedOutCode ||
		!strings.Contains(failure["detail"].(string), "30 分钟") {
		t.Fatalf("a timed-out request in the view: %v", got)
	}
	if item := f.checkItem(f.primary); item["generationRequest"] != nil {
		t.Fatalf("a timed-out request is still delivered: %v", item)
	}
	if stored := f.storedGenerationRequest(); stored.Status != generationPending {
		t.Fatalf("reading a timed-out request wrote it back: %+v", stored)
	}
	// 已有可用密钥：超时不影响就绪
	if codes := readinessCodes(t, f); len(codes) != 0 {
		t.Fatalf("a timed-out regeneration made a configured tenant unready: %v", codes)
	}

	// 超时之后才交回：409 KEYSTORE_GENERATION_STALE（签名闸据此丢弃），超时写回库，密钥不变
	before, _ := f.s.buildKeystoreStateFor(t.Context(), f.db, f.tenant)
	upload := f.sealedUpload(f.slug, f.packageName, alias, newCertificateSHA256(), f.primary.X25519.PublicKey().Bytes(), recoveryKey.Private.PublicKey().Bytes())
	if r := f.deliver(f.primary, first, upload, f.primary.ID, f.primary.Ed25519); r.Code != http.StatusConflict || problemCode(t, r) != generationStaleCode {
		t.Fatalf("delivering a timed-out request: %d %s", r.Code, r.Body.String())
	}
	if stored := f.storedGenerationRequest(); stored.Status != generationFailed || stored.Error == nil || stored.Error.Code != generationTimedOutCode || stored.CompletedAt != optString(iso(now)) {
		t.Fatalf("a timed-out delivery must be recorded as timed out: %+v", stored)
	}
	if after, _ := f.s.buildKeystoreStateFor(t.Context(), f.db, f.tenant); after.Version != before.Version || after.Record.CertificateSHA256 != before.Record.CertificateSHA256 {
		t.Fatalf("a timed-out delivery replaced the keystore: %+v", after.Record)
	}
	if f.auditCount(f.tenant, "build_keystore_generation_failed") != 1 {
		t.Fatal("the timed-out delivery was not audited as failed exactly once")
	}

	// 超时的请求不挡新的；新的超时之后报失败：同样 409，超时写回库
	second := requestAt()
	now = now.Add(generationTimeout + time.Second)
	if r := f.do(http.MethodPost, "/v1/signer/keystore-generations/"+second+"/fail", f.primary.Token, nil, map[string]any{"code": "TRUST_ROOTS_CHANGED", "detail": "late"}); r.Code != http.StatusConflict || problemCode(t, r) != generationStaleCode {
		t.Fatalf("reporting a failure after the timeout: %d %s", r.Code, r.Body.String())
	}
	if stored := f.storedGenerationRequest(); stored.RequestID != second || stored.Status != generationFailed || stored.Error == nil || stored.Error.Code != generationTimedOutCode {
		t.Fatalf("a failure reported after the timeout: %+v", stored)
	}
	if f.auditCount(f.tenant, "build_keystore_generation_failed") != 2 {
		t.Fatal("the timed-out failure report was not audited")
	}

	// 还没有密钥的租户：超时就是就绪问题 KEYSTORE_GENERATION_FAILED，带上超时的原因
	if _, err := f.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key IN (?,?,?)`, f.tenant, buildKeystoreConfigKey, releaseAndroidIdentityConfigKey, buildKeystoreCheckConfigKey); err != nil {
		t.Fatal(err)
	}
	if r := f.generate(map[string]any{"packageName": f.packageName, "expectedVersion": 0, "releaseIdentityExpectedVersion": 0, "reason": "first key", "confirm": true}); r.Code != http.StatusAccepted {
		t.Fatalf("first generate: %d %s", r.Code, r.Body.String())
	}
	if codes := readinessCodes(t, f); !containsString(codes, readinessGenerationPending) {
		t.Fatalf("readiness of a fresh first generation: %v", codes)
	}
	now = now.Add(generationTimeout + time.Second)
	readiness, err := f.s.signerReadinessFor(t.Context(), f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range readiness.Problems {
		if p.Code == readinessGenerationPending {
			t.Fatalf("a timed-out first generation is still pending: %v", readiness.Problems)
		}
		found = found || (p.Code == readinessGenerationFailed && strings.Contains(p.Detail, generationTimedOutCode))
	}
	if !found {
		t.Fatalf("a timed-out first generation: %v", readiness.Problems)
	}
}

// 恢复公钥吊销之后，已有密钥视图里仍然列着它（密文已经发给它了），但要看得出哪几把已吊销：
// revokedRecoveryRecipients 是 recoveryRecipients 里已吊销的子集。
func TestDBKeystoreViewMarksRevokedRecoveryRecipients(t *testing.T) {
	f := newGateFixture(t, 135)
	if view := f.keystoreView(); len(view["recoveryRecipients"].([]any)) != 0 || view["revokedRecoveryRecipients"] == nil || len(view["revokedRecoveryRecipients"].([]any)) != 0 {
		t.Fatalf("a keystore without recovery recipients: %v / %v", view["recoveryRecipients"], view["revokedRecoveryRecipients"])
	}
	first := f.registerRecoveryKey("recovery-one")
	second := f.registerRecoveryKey("recovery-two")
	keystoreVersion, identityVersion := f.keystoreVersions()
	upload := f.sealedUpload(f.slug, f.packageName, "release", f.apkSigner.sha256(), f.primary.X25519.PublicKey().Bytes(),
		first.Private.PublicKey().Bytes(), second.Private.PublicKey().Bytes())
	if saved := f.saveKeystoreRequest(map[string]any{"upload": upload, "packageName": f.packageName, "signerSha256": f.apkSigner.sha256(),
		"expectedVersion": keystoreVersion, "releaseIdentityExpectedVersion": identityVersion, "reason": "import with two recovery keys", "confirm": true}); saved.Code != http.StatusOK {
		t.Fatalf("import: %d %s", saved.Code, saved.Body.String())
	} else if revoked := decodeBody(t, saved)["revokedRecoveryRecipients"]; revoked == nil || len(revoked.([]any)) != 0 {
		t.Fatalf("the save response must carry revokedRecoveryRecipients too: %v", revoked)
	}
	sorted := []string{first.SHA256, second.SHA256}
	sort.Strings(sorted)
	joined := func(values []any) string {
		out := []string{}
		for _, v := range values {
			out = append(out, v.(string))
		}
		return strings.Join(out, ",")
	}
	view := f.keystoreView()
	if joined(view["recoveryRecipients"].([]any)) != strings.Join(sorted, ",") || len(view["revokedRecoveryRecipients"].([]any)) != 0 {
		t.Fatalf("two live recovery recipients: %v / %v", view["recoveryRecipients"], view["revokedRecoveryRecipients"])
	}
	f.revokeRecoveryKey(first.ID)
	view = f.keystoreView()
	if joined(view["recoveryRecipients"].([]any)) != strings.Join(sorted, ",") || joined(view["revokedRecoveryRecipients"].([]any)) != first.SHA256 {
		t.Fatalf("one revoked recovery recipient: %v / %v", view["recoveryRecipients"], view["revokedRecoveryRecipients"])
	}
	f.revokeRecoveryKey(second.ID)
	view = f.keystoreView()
	if joined(view["recoveryRecipients"].([]any)) != strings.Join(sorted, ",") || joined(view["revokedRecoveryRecipients"].([]any)) != strings.Join(sorted, ",") {
		t.Fatalf("every recovery recipient revoked: %v / %v", view["recoveryRecipients"], view["revokedRecoveryRecipients"])
	}
}

// 导出：当前密钥的密文文件原样下载、写审计；没有可用密钥 404。导入可以带恢复收件人，但不强制。
func TestDBKeystoreExportAndImportWithRecoveryRecipients(t *testing.T) {
	f := newGateFixture(t, 133)
	export := func() *httptest.ResponseRecorder {
		c, recorder := testContext(t, f.tenant, http.MethodGet, "/v1/admin/build-keystore/export", nil)
		f.s.exportBuildKeystore(c)
		return recorder
	}
	r := export()
	state, _ := f.s.buildKeystoreStateFor(t.Context(), f.db, f.tenant)
	var exported keystorebox.Upload
	if r.Code != http.StatusOK || json.Unmarshal(r.Body.Bytes(), &exported) != nil || !strings.Contains(r.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("export: %d %s", r.Code, r.Body.String())
	}
	parsed, err := keystorebox.ParseUpload(r.Body.Bytes())
	want, _ := json.Marshal(state.Upload)
	got, _ := json.Marshal(parsed)
	if err != nil || !bytes.Equal(want, got) {
		t.Fatalf("the exported file differs from the stored upload: %v", err)
	}
	if f.auditCount(f.tenant, "build_keystore_exported") != 1 {
		t.Fatal("the export was not audited")
	}

	recoveryKey := f.registerRecoveryKey("platform-recovery")
	keystoreVersion, identityVersion := f.keystoreVersions()
	importBody := func(upload keystorebox.Upload) map[string]any {
		return map[string]any{"upload": upload, "packageName": f.packageName, "signerSha256": f.apkSigner.sha256(),
			"expectedVersion": keystoreVersion, "releaseIdentityExpectedVersion": identityVersion, "reason": "import with recovery", "confirm": true}
	}
	withRecovery := f.sealedUpload(f.slug, f.packageName, "release", f.apkSigner.sha256(), f.primary.X25519.PublicKey().Bytes(), recoveryKey.Private.PublicKey().Bytes())
	if saved := f.saveKeystoreRequest(importBody(withRecovery)); saved.Code != http.StatusOK {
		t.Fatalf("import with a recovery recipient: %d %s", saved.Code, saved.Body.String())
	} else if recipients := decodeBody(t, saved)["recoveryRecipients"].([]any); len(recipients) != 1 || recipients[0] != recoveryKey.SHA256 {
		t.Fatalf("recovery recipients after import: %v", recipients)
	}
	keystoreVersion, identityVersion = f.keystoreVersions()
	stranger, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if saved := f.saveKeystoreRequest(importBody(f.sealedUpload(f.slug, f.packageName, "release", f.apkSigner.sha256(), f.primary.X25519.PublicKey().Bytes(), stranger.PublicKey().Bytes()))); saved.Code != http.StatusUnprocessableEntity || problemCode(t, saved) != "BUILD_KEYSTORE_RECIPIENT_UNKNOWN" {
		t.Fatalf("import with an unknown recipient: %d %s", saved.Code, saved.Body.String())
	}

	if _, err := f.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, f.tenant, buildKeystoreConfigKey); err != nil {
		t.Fatal(err)
	}
	if r := export(); r.Code != http.StatusNotFound || problemCode(t, r) != "BUILD_KEYSTORE_NOT_CONFIGURED" {
		t.Fatalf("export without a keystore: %d %s", r.Code, r.Body.String())
	}
}

// ---- 纯函数 ----

// 安装包清单里的文件名：真实签名闸包带 @ 的 unit 模板（deploy/setup/build-bundles.sh 产出的样子）要收；
// 绝对路径、空段、. 与 .. 段一律不收。
func TestMachineBundleManifestFileNames(t *testing.T) {
	file := func(name string) machineBundleFile {
		return machineBundleFile{Name: name, Size: 10, SHA256: strings.Repeat("a", 64)}
	}
	manifest := func(names ...string) machineBundleManifestDoc {
		files := []machineBundleFile{}
		for _, name := range names {
			files = append(files, file(name))
		}
		return machineBundleManifestDoc{Format: machineBundleManifestFormat, Commit: strings.Repeat("0", 40), Bundles: map[string]machineBundle{
			machineRoleSigner: {Archive: "signer.tar.gz", ArchiveSHA256: strings.Repeat("b", 64), ArchiveSize: 100, Files: files},
		}}
	}
	real := []string{
		"README.md", "bin/signer", "bin/signer-check", "install.sh",
		"templates/rn-signer-@INSTANCE@-check.socket", "templates/rn-signer-@INSTANCE@-check@.service",
		"templates/rn-signer-@INSTANCE@.env", "templates/rn-signer-@INSTANCE@.service",
	}
	if _, err := manifest(real...).bundleFor(machineRoleSigner); err != nil {
		t.Fatalf("the real signer bundle file names were refused: %v", err)
	}
	for _, bad := range []string{"/etc/passwd", "../outside", "bin/../../x", "bin//signer", "bin/", "./install.sh", "bin/./signer", "", "bin/sig ner", `bin\signer`} {
		if _, err := manifest(append(real, bad)...).bundleFor(machineRoleSigner); err == nil {
			t.Fatalf("the bundle file name %q was accepted", bad)
		}
	}
	if _, err := manifest("bin/signer").bundleFor(machineRoleBuilder); err == nil {
		t.Fatal("a manifest without a builder bundle was accepted for a builder")
	}
}

func TestDefaultGenerationAliasIsAValidAlias(t *testing.T) {
	for slug, want := range map[string]string{
		"AnyFun":                 "anyfun-release",
		"predict-kim":            "predict-kim-release",
		"a.b_c":                  "a.b_c-release",
		strings.Repeat("X", 100): strings.Repeat("x", 56) + "-release",
	} {
		if got := defaultGenerationAlias(slug); got != want || len(got) > 64 {
			t.Fatalf("alias for %q: %q, want %q", slug, got, want)
		}
	}
}

// 生成请求记录的状态推导：发起之后两个版本任何一个变了，挂着的请求算失败（过期）；挂了超过 30 分钟算失败
// （超时，版本变了优先报过期）；完成、失败的不变。
func TestGenerationRequestEffectiveStatus(t *testing.T) {
	requestedAt := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	fresh := requestedAt.Add(generationTimeout - time.Millisecond)
	pending := keystoreGenerationRequest{Status: generationPending, KeystoreVersion: 3, ReleaseIdentityVersion: 5, RequestedAt: iso(requestedAt)}
	if got := pending.effective(3, 5, fresh); got.Status != generationPending || got.Error != nil {
		t.Fatalf("an untouched pending request: %+v", got)
	}
	if got := pending.effective(3, 5, requestedAt.Add(generationTimeout)); got.Status != generationPending {
		t.Fatalf("a request exactly at the timeout is still pending: %+v", got)
	}
	for _, versions := range [][2]int{{4, 5}, {3, 6}, {0, 0}} {
		for _, now := range []time.Time{fresh, requestedAt.Add(time.Hour)} {
			if got := pending.effective(versions[0], versions[1], now); got.Status != generationFailed || got.Error == nil || got.Error.Code != generationStaleCode {
				t.Fatalf("versions %v at %s: %+v", versions, now, got)
			}
		}
	}
	timedOut := pending.effective(3, 5, requestedAt.Add(generationTimeout+time.Millisecond))
	if timedOut.Status != generationFailed || timedOut.Error == nil || timedOut.Error.Code != generationTimedOutCode ||
		!strings.Contains(timedOut.Error.Detail, "30 分钟") || !strings.Contains(timedOut.Error.Detail, "重新发起") {
		t.Fatalf("a request pending for longer than the timeout: %+v", timedOut)
	}
	if pending.Status != generationPending || pending.Error != nil {
		t.Fatalf("effective changed the stored request: %+v", pending)
	}
	done := keystoreGenerationRequest{Status: generationDone, KeystoreVersion: 3, ReleaseIdentityVersion: 5, RequestedAt: iso(requestedAt)}
	if got := done.effective(4, 6, requestedAt.Add(time.Hour)); got.Status != generationDone {
		t.Fatalf("a done request: %+v", got)
	}
	// 发起时间读不出来的记录读的时候就当坏记录（errGenerationRequestInvalid），不会走到推导
	malformed := keystoreGenerationRequest{RequestID: "kgr_" + randomID(16), PackageName: "com.example.app", Alias: "release", RequestedAt: "yesterday", Status: generationPending}
	if err := malformed.validate(); err == nil {
		t.Fatal("a request with an unreadable requestedAt passed validation")
	}
	malformed.RequestedAt = iso(requestedAt)
	if err := malformed.validate(); err != nil {
		t.Fatalf("a well-formed request: %v", err)
	}
}
