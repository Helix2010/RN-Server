package api

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/secretbox"
	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/provenance"
	"github.com/gin-gonic/gin"
)

// 签名闸库测的公共夹具：一个配齐了的租户（App 身份、发布存储、OTA 证书、v3 签名密钥、
// 主签名闸已确认并试签通过）、一台构建机、主备两台签名闸，以及一个走真实路由表的服务端。
//
// 机器的令牌与私钥都是现场生成的，只在测试进程里。

const gateAdminKey = "gate-admin-key-for-tests"

type gateMachine struct {
	ID      string
	Name    string
	Role    string
	Token   string
	Ed25519 ed25519.PrivateKey
	X25519  *ecdh.PrivateKey
}

func newGateMachine(t *testing.T, role, name string) gateMachine {
	t.Helper()
	token, err := newMachineToken()
	if err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := gateMachine{ID: machineIDPrefix + "_" + randomID(16), Name: name, Role: role, Token: token, Ed25519: signing}
	if role == machineRoleSigner {
		if m.X25519, err = ecdh.X25519().GenerateKey(rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func (m gateMachine) ed25519Public() []byte { return m.Ed25519.Public().(ed25519.PublicKey) }

func (m gateMachine) recipient() string { return fingerprint.SHA256Hex(m.X25519.PublicKey().Bytes()) }

// record 是这台机器在 build.machines 里 active 状态的样子。签名闸的本机角色默认与登记的主备一致
// （本机已经 promote 过）；要测两边对不上时直接改返回值。
func (m gateMachine) record(signerRole string) buildMachine {
	record := buildMachine{
		ID: m.ID, Role: m.Role, Name: m.Name, Status: machineStatusActive, TokenSHA256: sha256Hex(m.Token),
		AcceptedBy: "tester@example.com", AcceptedAt: optString(iso(time.Now().UTC())),
		CreatedBy: "tester@example.com", CreatedAt: iso(time.Now().UTC()),
	}
	if m.Role == machineRoleBuilder {
		record.PublicKey = optString(base64.StdEncoding.EncodeToString(m.ed25519Public()))
		record.PublicKeySHA256 = optString(fingerprint.SHA256Hex(m.ed25519Public()))
		return record
	}
	record.SignerRole = optString(signerRole)
	record.ReportedLocalRole, record.ReportedLocalRoleAt = optString(signerRole), optString(iso(time.Now().UTC()))
	record.PublicKey = optString(base64.StdEncoding.EncodeToString(m.X25519.PublicKey().Bytes()))
	record.PublicKeySHA256 = optString(m.recipient())
	record.Ed25519PublicKey = optString(base64.StdEncoding.EncodeToString(m.ed25519Public()))
	record.Ed25519PublicKeySHA256 = optString(fingerprint.SHA256Hex(m.ed25519Public()))
	return record
}

type gateFixture struct {
	t           *testing.T
	s           *server
	db          *sql.DB
	store       *fakeObjectStore
	router      http.Handler
	tenant      string
	slug        string
	packageName string
	apkSigner   apkSigner
	builder     gateMachine
	primary     gateMachine
	standby     gateMachine
}

// newGateFixture 建好一个"主签名闸已就绪"的租户。
func newGateFixture(t *testing.T, seed int) *gateFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := openTestDB(t)
	box, err := secretbox.New(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	if err != nil {
		t.Fatal(err)
	}
	store := newFakeObjectStore()
	s := &server{
		db: db, secrets: box, objects: fixedObjectFactory{client: store}, tenant: newTenantResolver(db),
		attempts: map[string]attempt{},
		cfg: config.Config{
			Environment: "development", ArtifactMaxSizeBytes: 8 << 20, ArtifactVerifyTimeout: 30, ArtifactUploadTTL: 900,
			ArtifactUploadMode: "proxy", MySQLQueryTimeout: 10, AdminAPIKey: gateAdminKey, AdminAPIActor: "tester@example.com",
			PlatformAdminUsernames: []string{"tester@example.com"},
		},
	}
	// 机器登记是平台级单行、任务队列跨租户：每个用例从干净的全局状态开始
	if _, err := db.Exec(`DELETE FROM app_configs WHERE tenant_id=0 AND config_key=?`, buildMachinesConfigKey); err != nil {
		t.Fatal(err)
	}
	f := &gateFixture{t: t, s: s, db: db, store: store, tenant: testTenant(seed)}
	f.slug = seedBuildTenant(t, s, f.tenant)
	f.packageName = "com.gate.t" + strconv.Itoa(seed) + "x" + uniqueSuffix()
	f.apkSigner = newAPKSigner(t)
	seedBuildIdentityWith(t, db, f.tenant, f.slug, f.packageName, f.apkSigner.sha256())
	storage, _ := json.Marshal(storedReleaseStorage{Provider: "s3", Region: "us-east-1", Bucket: "rn-test"})
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newAPKSigner(t).certificate})
	otaKey, _ := json.Marshal(otaSigningKey{KeyID: "main", PrivateKey: "not-used-by-these-tests", Certificate: string(certificate)})
	for key, value := range map[string][]byte{releaseStorageConfigKey: storage, otaSigningConfigKey: otaKey} {
		if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,'tester',UTC_TIMESTAMP(3))`, f.tenant, key, value); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
	}
	f.builder = newGateMachine(t, machineRoleBuilder, "builder-"+uniqueSuffix())
	f.primary = newGateMachine(t, machineRoleSigner, "signer-a-"+uniqueSuffix())
	f.standby = newGateMachine(t, machineRoleSigner, "signer-b-"+uniqueSuffix())
	f.writeMachines(f.builder.record(""), f.primary.record(signerRolePrimary), f.standby.record(signerRoleStandby))
	s.machines = machineRegistryCache{}
	f.router = s.routes()

	f.uploadKeystore(f.primary, f.standby)
	f.reportCheck(f.primary, true, "ok")
	return f
}

func (f *gateFixture) writeMachines(machines ...buildMachine) {
	f.t.Helper()
	snapshot, err := readMachineRegistry(context.Background(), f.db, false)
	if err != nil {
		f.t.Fatal(err)
	}
	tx, err := f.db.Begin()
	if err != nil {
		f.t.Fatal(err)
	}
	defer tx.Rollback()
	applied, err := writeMachineRegistry(context.Background(), tx, buildMachinesDoc{Machines: machines}, snapshot.Version, "tester", time.Now().UTC())
	if err != nil || !applied {
		f.t.Fatalf("write machines: applied=%v err=%v", applied, err)
	}
	if err := tx.Commit(); err != nil {
		f.t.Fatal(err)
	}
}

// keystoreUpload 造一份离线工具会产出的 v3 上传文件，加密给 recipients。
func (f *gateFixture) keystoreUpload(slug, packageName, certificate string, recipients ...gateMachine) keystorebox.Upload {
	f.t.Helper()
	fingerprints := []string{}
	for _, r := range recipients {
		fingerprints = append(fingerprints, r.recipient())
	}
	sort.Strings(fingerprints)
	p12 := make([]byte, 256)
	_, _ = rand.Read(p12)
	plaintext := keystorebox.Plaintext{
		Purpose: keystorebox.Purpose, TenantSlug: slug, PackageName: packageName, CertificateSHA256: certificate,
		KeyAlias: "release", Recipients: fingerprints, CreatedAt: "2026-09-16T00:00:00Z",
		P12Base64: base64.StdEncoding.EncodeToString(p12), StorePassword: "test-store-password", KeyPassword: "test-key-password",
	}
	upload := keystorebox.Upload{
		Format: keystorebox.UploadFormat, TenantSlug: slug, PackageName: packageName, KeyAlias: "release",
		CertificateSHA256: certificate, CreatedAt: "2026-09-16T00:00:00Z",
	}
	for _, r := range recipients {
		box, err := keystorebox.Seal(plaintext, r.X25519.PublicKey().Bytes())
		if err != nil {
			f.t.Fatalf("seal: %v", err)
		}
		upload.Boxes = append(upload.Boxes, box)
	}
	return upload
}

// saveKeystoreRequest 走 PUT /v1/admin/build-keystore 的处理函数。
func (f *gateFixture) saveKeystoreRequest(body map[string]any) *httptest.ResponseRecorder {
	f.t.Helper()
	c, recorder := testContext(f.t, f.tenant, http.MethodPut, "/v1/admin/build-keystore", body)
	f.s.saveBuildKeystore(c)
	return recorder
}

func (f *gateFixture) keystoreVersions() (int, int) {
	f.t.Helper()
	versionOf := func(key string) int {
		var version int
		err := f.db.QueryRow(`SELECT version FROM app_configs WHERE tenant_id=? AND config_key=?`, f.tenant, key).Scan(&version)
		if err != nil && err != sql.ErrNoRows {
			f.t.Fatal(err)
		}
		return version
	}
	return versionOf(buildKeystoreConfigKey), versionOf(releaseAndroidIdentityConfigKey)
}

func (f *gateFixture) uploadKeystore(recipients ...gateMachine) {
	f.t.Helper()
	keystoreVersion, identityVersion := f.keystoreVersions()
	recorder := f.saveKeystoreRequest(map[string]any{
		"upload": f.keystoreUpload(f.slug, f.packageName, f.apkSigner.sha256(), recipients...), "packageName": f.packageName,
		"signerSha256": f.apkSigner.sha256(), "expectedVersion": keystoreVersion, "releaseIdentityExpectedVersion": identityVersion,
		"reason": "upload test keystore", "confirm": true,
	})
	if recorder.Code != http.StatusOK {
		f.t.Fatalf("upload keystore: %d %s", recorder.Code, recorder.Body.String())
	}
}

func (f *gateFixture) currentDigest() string {
	f.t.Helper()
	_, digest, problems, err := f.s.trustRootsFor(context.Background(), f.tenant)
	if err != nil || digest == "" {
		f.t.Fatalf("trust roots: %v %v", err, problems)
	}
	return digest
}

// reportCheck 以签名闸身份上报对当前密钥的检查结果。
func (f *gateFixture) reportCheck(machine gateMachine, confirmed bool, trialSign string) {
	f.t.Helper()
	keystoreVersion, _ := f.keystoreVersions()
	digest := f.currentDigest()
	item := map[string]any{"tenantSlug": f.slug, "keystoreVersion": keystoreVersion, "decrypt": "ok", "confirmed": confirmed,
		"confirmedTrustRootsDigest": nil, "trialSign": trialSign, "error": nil}
	if confirmed {
		item["confirmedTrustRootsDigest"] = digest
	}
	recorder := f.do(http.MethodPost, "/v1/signer/keystore-checks", machine.Token, nil, map[string]any{"localRole": f.localRoleOf(machine), "items": []any{item}})
	if recorder.Code != http.StatusNoContent {
		f.t.Fatalf("report check: %d %s", recorder.Code, recorder.Body.String())
	}
}

// localRoleOf 是这台签名闸现在登记里记的本机角色（没有记过就用登记的主备），上报时原样带回，不改变它。
func (f *gateFixture) localRoleOf(machine gateMachine) string {
	f.t.Helper()
	snapshot, err := readMachineRegistry(context.Background(), f.db, false)
	if err != nil {
		f.t.Fatal(err)
	}
	index, found := snapshot.Doc.find(machine.ID)
	if !found {
		f.t.Fatalf("machine %s is not registered", machine.ID)
	}
	m := snapshot.Doc.Machines[index]
	if m.ReportedLocalRole != "" {
		return string(m.ReportedLocalRole)
	}
	if m.SignerRole != "" {
		return string(m.SignerRole)
	}
	return signerRoleStandby
}

func (f *gateFixture) readyItem() map[string]any {
	return map[string]any{"tenantSlug": f.slug, "packageName": f.packageName, "certificateSha256": f.apkSigner.sha256(), "trustRootsDigest": f.currentDigest()}
}

// do 走真实路由表。body 是 []byte 时按 application/octet-stream 发，否则按 JSON。
func (f *gateFixture) do(method, path, token string, headers map[string]string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	var reader io.Reader = http.NoBody
	contentType := "application/json"
	switch value := body.(type) {
	case nil:
	case []byte:
		reader, contentType = bytes.NewReader(value), octetStream
	default:
		raw, err := json.Marshal(value)
		if err != nil {
			f.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	request := httptest.NewRequest(method, path, reader)
	request.Header.Set("content-type", contentType)
	if token != "" {
		request.Header.Set(machineTokenHeader, token)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	f.router.ServeHTTP(recorder, request)
	return recorder
}

// adminDo 以平台管理员（x-admin-key）调管理端接口。
func (f *gateFixture) adminDo(method, path string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.do(method, path, "", map[string]string{"x-admin-key": gateAdminKey}, body)
}

// queueBuild 排一个安装包任务（走管理端处理函数）。
func (f *gateFixture) queueBuild(version string, buildNumber int) string {
	f.t.Helper()
	c, recorder := testContext(f.t, f.tenant, http.MethodPost, "/v1/admin/builds", map[string]any{
		"platform": "android", "gitRef": "main", "version": version, "buildNumber": buildNumber,
		"reason": "signing gate test", "confirm": true, "releaseNotes": map[string]any{"zh-CN": []string{"测试"}},
	})
	f.s.createBuildJob(c)
	if recorder.Code != http.StatusCreated {
		f.t.Fatalf("queue %s/%d: %d %s", version, buildNumber, recorder.Code, recorder.Body.String())
	}
	return decodeBody(f.t, recorder)["id"].(string)
}

func (f *gateFixture) claimBuild() map[string]any {
	f.t.Helper()
	recorder := f.do(http.MethodPost, "/v1/build-agent/claim", f.builder.Token, nil, map[string]any{"platforms": []string{"android"}, "kinds": []string{"apk", "ota"}})
	if recorder.Code != http.StatusOK {
		f.t.Fatalf("claim build: %d %s", recorder.Code, recorder.Body.String())
	}
	return decodeBody(f.t, recorder)
}

func ginParam(key, value string) gin.Param { return gin.Param{Key: key, Value: value} }

func attemptHeaders(name string, attempt int) map[string]string {
	return map[string]string{name: strconv.Itoa(attempt)}
}

type deliveredBuild struct {
	unsigned  []byte
	sbom      []byte
	commit    string
	native    string
	statement provenance.Statement
	envelope  provenance.Envelope
}

// unsignedAPK 是这个租户某个版本的未签名包。
func (f *gateFixture) unsignedAPK(version string, buildNumber int) []byte {
	return buildSignedAPK(f.t, apkSpec{PackageName: f.packageName, VersionCode: buildNumber, VersionName: version, MinSDK: 24,
		ApplicationID: tenantApplicationID, Fingerprint: gateNativeFingerprint}, nil)
}

const gateNativeFingerprint = "0123456789abcdef0123456789abcdef01234567"

// deliverBuild 以构建机身份上传未签名包与 SBOM，并交付出处签名，任务转为 built。
func (f *gateFixture) deliverBuild(job map[string]any) deliveredBuild {
	f.t.Helper()
	id := job["id"].(string)
	attempt := int(job["attempt"].(float64))
	version := job["version"].(string)
	buildNumber := int(job["buildNumber"].(float64))
	d := deliveredBuild{
		unsigned: f.unsignedAPK(version, buildNumber),
		sbom:     []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`),
		commit:   strings.Repeat("c", 40),
		native:   gateNativeFingerprint,
	}
	headers := attemptHeaders(buildAttemptHeader, attempt)
	if r := f.do(http.MethodPut, "/v1/build-agent/jobs/"+id+"/unsigned/upload", f.builder.Token, headers, d.unsigned); r.Code != http.StatusOK {
		f.t.Fatalf("upload unsigned: %d %s", r.Code, r.Body.String())
	}
	if r := f.do(http.MethodPut, "/v1/build-agent/jobs/"+id+"/sbom/upload", f.builder.Token, headers, d.sbom); r.Code != http.StatusOK {
		f.t.Fatalf("upload sbom: %d %s", r.Code, r.Body.String())
	}
	d.statement = provenance.Statement{
		Version: provenance.Version, Purpose: provenance.Purpose, JobID: id, Attempt: attempt, TenantSlug: f.slug,
		PackageName: f.packageName, VersionCode: int64(buildNumber), VersionName: version, CommitSHA: d.commit,
		UnsignedSHA256: sha256HexBytes(d.unsigned), UnsignedSize: int64(len(d.unsigned)), SBOMSHA256: sha256HexBytes(d.sbom),
		NativeFingerprint: d.native, BuilderID: f.builder.ID, BuiltAt: time.Now().UTC().Format(time.RFC3339),
	}
	envelope, err := provenance.Sign(d.statement, f.builder.Ed25519)
	if err != nil {
		f.t.Fatal(err)
	}
	d.envelope = envelope
	if r := f.do(http.MethodPost, "/v1/build-agent/jobs/"+id+"/built", f.builder.Token, headers, map[string]any{
		"commitSha": d.commit, "nativeFingerprint": d.native, "provenance": envelope, "logTail": []string{"built"},
	}); r.Code != http.StatusNoContent {
		f.t.Fatalf("built: %d %s", r.Code, r.Body.String())
	}
	return d
}

// matchesDeliveryKey：对象键形如 …/tenants/<租户>/build-jobs/<任务>/<a或s编号>/<每次上传的随机段>/<文件名>。
func matchesDeliveryKey(key, tenant, jobID, segment, name string) bool {
	return regexp.MustCompile(`(^|/)tenants/` + regexp.QuoteMeta(tenant) + `/build-jobs/` + regexp.QuoteMeta(jobID) + `/` +
		regexp.QuoteMeta(segment) + `/[A-Za-z0-9_-]{12}/` + regexp.QuoteMeta(name) + `$`).MatchString(key)
}

func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// claimSign 以主签名闸身份认领；返回 nil 表示 204。
func (f *gateFixture) claimSign(machine gateMachine, ready ...map[string]any) map[string]any {
	f.t.Helper()
	if ready == nil {
		ready = []map[string]any{f.readyItem()}
	}
	r := f.do(http.MethodPost, "/v1/signer/claim", machine.Token, nil, map[string]any{"ready": ready})
	switch r.Code {
	case http.StatusNoContent:
		return nil
	case http.StatusOK:
		return decodeBody(f.t, r)
	}
	f.t.Fatalf("sign claim: %d %s", r.Code, r.Body.String())
	return nil
}

// signAndUpload 用夹具的签名证书签一个包并以签名闸身份上传，返回已签名包。
func (f *gateFixture) signAndUpload(jobID string, signAttempt int, version string, buildNumber int) []byte {
	f.t.Helper()
	signed := buildSignedAPK(f.t, apkSpec{PackageName: f.packageName, VersionCode: buildNumber, VersionName: version, MinSDK: 24,
		ApplicationID: tenantApplicationID, Fingerprint: gateNativeFingerprint}, &f.apkSigner)
	if r := f.do(http.MethodPut, "/v1/signer/jobs/"+jobID+"/signed/upload", f.primary.Token, attemptHeaders(signAttemptHeader, signAttempt), signed); r.Code != http.StatusOK {
		f.t.Fatalf("signed upload: %d %s", r.Code, r.Body.String())
	}
	return signed
}

func (f *gateFixture) completeBody(signed []byte, unsigned []byte) map[string]any {
	return map[string]any{
		"signedSha256": sha256HexBytes(signed), "signedSize": len(signed), "certificateSha256": f.apkSigner.sha256(),
		"unsignedSha256": sha256HexBytes(unsigned), "nativeFingerprint": gateNativeFingerprint,
	}
}

func (f *gateFixture) jobStatus(id string) buildJob {
	f.t.Helper()
	job, err := scanBuildJob(f.db.QueryRow(`SELECT `+buildJobColumns+` FROM build_jobs WHERE id=?`, id))
	if err != nil {
		f.t.Fatalf("load job %s: %v", id, err)
	}
	return job
}

// setKeystoreValue 直接改库里 build.keystore 这一行（模拟记录被改坏），expression 用 ? 接 arg。
func (f *gateFixture) setKeystoreValue(expression string, arg any) {
	f.t.Helper()
	if _, err := f.db.Exec(`UPDATE app_configs SET config_value=`+expression+`,version=version+1 WHERE tenant_id=? AND config_key=?`, arg, f.tenant, buildKeystoreConfigKey); err != nil {
		f.t.Fatal(err)
	}
}

// ageSignOutcome 把最近一次没签成的时间往前拨，越过"暂不能签"的冷却期。
func (f *gateFixture) ageSignOutcome(id string) {
	f.t.Helper()
	f.setJob(id, "sign_outcome=JSON_SET(sign_outcome,'$.at',?)", iso(time.Now().UTC().Add(-signDeferralCooldown-time.Second)))
}

func (f *gateFixture) setJob(id, assignments string, args ...any) {
	f.t.Helper()
	if _, err := f.db.Exec(`UPDATE build_jobs SET `+assignments+` WHERE id=?`, append(args, id)...); err != nil {
		f.t.Fatalf("set job %s: %v", id, err)
	}
}

// seedBuildIdentityWith 是 seedBuildIdentity 的可指定包名与签名指纹版本。
func seedBuildIdentityWith(t *testing.T, db *sql.DB, tenant, slug, packageName, signer string) {
	t.Helper()
	now := time.Now().UTC()
	put := func(key string, value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,'test',?)`, tenant, key, raw, now); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
	}
	put(buildConfigKey, buildConfig{
		RepoDirectory: slug, DefaultGitRef: buildGitRef,
		Identity: appIdentity{AppName: "Seeded", Scheme: "seeded", APIBaseURL: "https://api.seeded.example"},
	})
	put(bootstrapSigningConfigKey, bootstrapSigningKey{KeyID: "main", PrivateKey: "unused-in-this-path", Address: "0x9269Ca361b9F0427ac883e89cD5B5fe113BBAD17"})
	put(releaseAndroidIdentityConfigKey, androidReleaseIdentity{PackageName: packageName, SignerSHA256: signer})
}
