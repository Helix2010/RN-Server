package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/machinekey"
	"github.com/gin-gonic/gin"
)

func TestMachineTokenShape(t *testing.T) {
	token, err := newMachineToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "rnm_") || len(token) != 4+43 || !validMachineTokenShape(token) {
		t.Fatalf("token shape: %q", token)
	}
	for _, bad := range []string{"", "rnm_", "rnm_short", strings.Repeat("a", 47), "rnm_" + strings.Repeat("!", 43)} {
		if validMachineTokenShape(bad) {
			t.Fatalf("%q accepted as a machine token", bad)
		}
	}
}

// 旧构建机只带 x-build-agent-token：回 426 说"要升级"，不是和令牌错了一样的 401。
func TestMachineAuthAsksLegacyAgentsToUpgrade(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &server{cfg: config.Config{Environment: "production"}}
	call := func(headers map[string]string) (int, string) {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/build-agent/claim", nil)
		for key, value := range headers {
			c.Request.Header.Set(key, value)
		}
		c.Set("requestId", "req_test")
		// db 为 nil：走到读登记就会 panic，证明这两种拒绝发生在读库之前
		s.machineAuth(machineRoleBuilder, false)(c)
		return recorder.Code, problemCode(t, recorder)
	}
	if code, problem := call(map[string]string{"x-build-agent-token": "the-old-shared-token"}); code != http.StatusUpgradeRequired || problem != "MACHINE_AUTH_UPGRADE_REQUIRED" {
		t.Fatalf("legacy header: %d %s", code, problem)
	}
	if code, problem := call(nil); code != http.StatusUnauthorized || problem != "MACHINE_AUTH_REQUIRED" {
		t.Fatalf("no credential: %d %s", code, problem)
	}
	if code, problem := call(map[string]string{machineTokenHeader: "not-a-machine-token"}); code != http.StatusUnauthorized || problem != "MACHINE_AUTH_REQUIRED" {
		t.Fatalf("malformed token: %d %s", code, problem)
	}
	// 管理端密钥开不了机器通道
	if code, _ := call(map[string]string{"x-admin-key": "admin-key"}); code != http.StatusUnauthorized {
		t.Fatalf("the admin key opened the machine channel: %d", code)
	}
}

// 令牌按角色隔离：构建机令牌调签名闸接口 403，反之亦然；公钥没被接受的机器只能登记公钥；
// 吊销即时生效（登记按版本缓存，吊销改了版本，下一个请求就读到）。
func TestDBMachineAuthRolesPendingKeyAndRevocation(t *testing.T) {
	f := newGateFixture(t, 51)
	if r := f.do(http.MethodPost, "/v1/signer/claim", f.builder.Token, nil, map[string]any{"ready": []any{}}); r.Code != http.StatusForbidden || problemCode(t, r) != "MACHINE_ROLE_FORBIDDEN" {
		t.Fatalf("a builder token on the signer channel: %d %s", r.Code, r.Body.String())
	}
	if r := f.do(http.MethodPost, "/v1/build-agent/claim", f.primary.Token, nil, map[string]any{"platforms": []string{"android"}, "kinds": []string{"apk"}}); r.Code != http.StatusForbidden || problemCode(t, r) != "MACHINE_ROLE_FORBIDDEN" {
		t.Fatalf("a signer token on the builder channel: %d %s", r.Code, r.Body.String())
	}
	if r := f.do(http.MethodGet, "/v1/signer/keystore-checks", "rnm_"+strings.Repeat("A", 43), nil, nil); r.Code != http.StatusUnauthorized {
		t.Fatalf("an unknown token: %d %s", r.Code, r.Body.String())
	}

	// 新建一台构建机：pending_key，只能调 public-key
	created := f.adminDo(http.MethodPost, "/v1/admin/platform/machines", map[string]any{
		"role": "builder", "name": "builder-new-" + uniqueSuffix(), "signerRole": nil, "expectedVersion": registryVersion(t, f), "reason": "add a builder", "confirm": true,
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create machine: %d %s", created.Code, created.Body.String())
	}
	body := decodeBody(t, created)
	token := body["token"].(string)
	machine := body["machine"].(map[string]any)
	if machine["status"] != "pending_key" {
		t.Fatalf("a new machine: %v", machine)
	}
	if r := f.do(http.MethodPost, "/v1/build-agent/claim", token, nil, map[string]any{"platforms": []string{"android"}, "kinds": []string{"apk"}}); r.Code != http.StatusForbidden || problemCode(t, r) != "MACHINE_KEY_NOT_ACCEPTED" {
		t.Fatalf("a pending machine claimed: %d %s", r.Code, r.Body.String())
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	public := private.Public().(ed25519.PublicKey)
	if r := f.do(http.MethodPost, "/v1/build-agent/public-key", token, nil, map[string]any{"publicKey": base64.StdEncoding.EncodeToString(public), "rotationSignature": nil}); r.Code != http.StatusOK {
		t.Fatalf("a pending machine could not report its key: %d %s", r.Code, r.Body.String())
	}

	// 吊销主构建机之后，它的下一个请求就是 401
	if r := f.do(http.MethodPost, "/v1/build-agent/claim", f.builder.Token, nil, map[string]any{"platforms": []string{"android"}, "kinds": []string{"apk"}}); r.Code != http.StatusNoContent {
		t.Fatalf("an active builder before revocation: %d %s", r.Code, r.Body.String())
	}
	revoked := f.adminDo(http.MethodPost, "/v1/admin/platform/machines/"+f.builder.ID+"/revoke", map[string]any{"expectedVersion": registryVersion(t, f), "reason": "machine compromised", "confirm": true})
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", revoked.Code, revoked.Body.String())
	}
	if r := f.do(http.MethodPost, "/v1/build-agent/claim", f.builder.Token, nil, map[string]any{"platforms": []string{"android"}, "kinds": []string{"apk"}}); r.Code != http.StatusUnauthorized {
		t.Fatalf("a revoked builder was still accepted: %d %s", r.Code, r.Body.String())
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/machines/"+f.builder.ID+"/revoke", map[string]any{"expectedVersion": registryVersion(t, f), "reason": "again", "confirm": true}); r.Code != http.StatusConflict || problemCode(t, r) != "MACHINE_ALREADY_REVOKED" {
		t.Fatalf("revoking twice: %d %s", r.Code, r.Body.String())
	}
}

func registryVersion(t *testing.T, f *gateFixture) int {
	t.Helper()
	snapshot, err := readMachineRegistry(t.Context(), f.db, false)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot.Version
}

// 管理端写登记：乐观锁、令牌只出现在新建响应里（不进登记原文以外的地方、不进审计）、
// 同时最多一台 primary、名称不重复、视图里没有令牌 sha256 和公钥原文。
func TestDBMachineAdminWrites(t *testing.T) {
	f := newGateFixture(t, 52)
	version := registryVersion(t, f)
	stale := f.adminDo(http.MethodPost, "/v1/admin/platform/machines", map[string]any{"role": "signer", "name": "signer-c", "signerRole": "standby", "expectedVersion": version - 1, "reason": "stale write", "confirm": true})
	if stale.Code != http.StatusConflict || problemCode(t, stale) != "MACHINES_VERSION_CONFLICT" {
		t.Fatalf("a stale registry write: %d %s", stale.Code, stale.Body.String())
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/machines", map[string]any{"role": "signer", "name": "signer-c", "signerRole": "primary", "expectedVersion": version, "reason": "second primary", "confirm": true}); r.Code != http.StatusConflict || problemCode(t, r) != "SIGNER_PRIMARY_EXISTS" {
		t.Fatalf("a second primary: %d %s", r.Code, r.Body.String())
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/machines", map[string]any{"role": "builder", "name": f.primary.Name, "signerRole": nil, "expectedVersion": version, "reason": "name clash", "confirm": true}); r.Code != http.StatusConflict || problemCode(t, r) != "MACHINE_NAME_TAKEN" {
		t.Fatalf("a duplicated name: %d %s", r.Code, r.Body.String())
	}
	for name, body := range map[string]map[string]any{
		"builder with signerRole": {"role": "builder", "name": "builder-x", "signerRole": "primary", "expectedVersion": version, "reason": "bad", "confirm": true},
		"signer without role":     {"role": "signer", "name": "signer-x", "signerRole": nil, "expectedVersion": version, "reason": "bad", "confirm": true},
		"bad name":                {"role": "builder", "name": "Builder X", "signerRole": nil, "expectedVersion": version, "reason": "bad", "confirm": true},
		"no confirm":              {"role": "builder", "name": "builder-x", "signerRole": nil, "expectedVersion": version, "reason": "bad", "confirm": false},
		"no expectedVersion":      {"role": "builder", "name": "builder-x", "signerRole": nil, "reason": "bad", "confirm": true},
	} {
		if r := f.adminDo(http.MethodPost, "/v1/admin/platform/machines", body); r.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, r.Code, r.Body.String())
		}
	}
	created := f.adminDo(http.MethodPost, "/v1/admin/platform/machines", map[string]any{"role": "signer", "name": "signer-c-" + uniqueSuffix(), "signerRole": "standby", "expectedVersion": version, "reason": "third signer", "confirm": true})
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	body := decodeBody(t, created)
	token := body["token"].(string)
	if body["version"] != float64(version+1) {
		t.Fatalf("version after create: %v", body["version"])
	}
	var audit string
	if err := f.db.QueryRow(`SELECT summary FROM audit_events WHERE tenant_id=0 AND action='build_machine_create' ORDER BY created_at DESC LIMIT 1`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(audit, token) || strings.Contains(audit, sha256Hex(token)) {
		t.Fatalf("the token reached the audit log: %s", audit)
	}
	list := f.adminDo(http.MethodGet, "/v1/admin/platform/machines", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list: %d", list.Code)
	}
	raw := list.Body.String()
	if strings.Contains(raw, token) || strings.Contains(raw, sha256Hex(token)) || strings.Contains(raw, "tokenSha256") ||
		strings.Contains(raw, base64.StdEncoding.EncodeToString(f.builder.ed25519Public())) {
		t.Fatalf("the machine list leaks tokens or raw public keys: %s", raw)
	}
	// 非平台管理员进不来
	f.s.cfg.PlatformAdminUsernames = []string{"someone-else@example.com"}
	f.router = f.s.routes()
	if r := f.adminDo(http.MethodGet, "/v1/admin/platform/machines", nil); r.Code != http.StatusForbidden {
		t.Fatalf("a tenant admin listed machines: %d", r.Code)
	}
}

// 公钥登记与接受：同钥幂等；已 active 的机器换钥要当前私钥签名；接受时指纹要完整对上；
// 切换主签名闸时原 primary 同一次写降为 standby。
func TestDBMachineKeyRotationAndSignerRoles(t *testing.T) {
	f := newGateFixture(t, 53)
	signerKey := func(machine gateMachine, x25519, signing []byte, signature any) *httptest.ResponseRecorder {
		return f.do(http.MethodPost, "/v1/signer/public-key", machine.Token, nil, map[string]any{
			"x25519PublicKey": base64.StdEncoding.EncodeToString(x25519), "ed25519PublicKey": base64.StdEncoding.EncodeToString(signing), "rotationSignature": signature,
		})
	}
	// 同一把：幂等
	same := signerKey(f.primary, f.primary.X25519.PublicKey().Bytes(), f.primary.ed25519Public(), nil)
	if same.Code != http.StatusOK || decodeBody(t, same)["pendingPublicKeySha256"] != nil {
		t.Fatalf("re-registering the same key: %d %s", same.Code, same.Body.String())
	}
	next := newGateMachine(t, machineRoleSigner, "unused")
	newX, newEd := next.X25519.PublicKey().Bytes(), next.ed25519Public()
	if r := signerKey(f.primary, newX, newEd, nil); r.Code != http.StatusForbidden || problemCode(t, r) != "MACHINE_KEY_ROTATION_UNPROVEN" {
		t.Fatalf("an unsigned rotation: %d %s", r.Code, r.Body.String())
	}
	forged, _ := machinekey.SignRotation(next.Ed25519, f.primary.ID, fingerprint.SHA256Hex(newX), fingerprint.SHA256Hex(newEd))
	if r := signerKey(f.primary, newX, newEd, base64.StdEncoding.EncodeToString(forged)); r.Code != http.StatusForbidden {
		t.Fatalf("a rotation signed with the new key instead of the current one: %d %s", r.Code, r.Body.String())
	}
	proof, err := machinekey.SignRotation(f.primary.Ed25519, f.primary.ID, fingerprint.SHA256Hex(newX), fingerprint.SHA256Hex(newEd))
	if err != nil {
		t.Fatal(err)
	}
	rotated := signerKey(f.primary, newX, newEd, base64.StdEncoding.EncodeToString(proof))
	if rotated.Code != http.StatusOK || decodeBody(t, rotated)["pendingPublicKeySha256"] != fingerprint.SHA256Hex(newX) {
		t.Fatalf("a proven rotation: %d %s", rotated.Code, rotated.Body.String())
	}
	// 旧公钥在新公钥被接受之前保持有效：主签名闸照常能领任务
	if r := f.do(http.MethodPost, "/v1/signer/claim", f.primary.Token, nil, map[string]any{"ready": []any{f.readyItem()}}); r.Code != http.StatusNoContent {
		t.Fatalf("the primary lost its channel while a rotation is pending: %d %s", r.Code, r.Body.String())
	}
	accept := func(machineID, digest string) *httptest.ResponseRecorder {
		return f.adminDo(http.MethodPost, "/v1/admin/platform/machines/"+machineID+"/accept-key", map[string]any{
			"publicKeySha256": digest, "expectedVersion": registryVersion(t, f), "reason": "verified on the machine", "confirm": true,
		})
	}
	if r := accept(f.primary.ID, strings.Repeat("0", 64)); r.Code != http.StatusConflict || problemCode(t, r) != "MACHINE_KEY_MISMATCH" {
		t.Fatalf("accepting a fingerprint that is not pending: %d %s", r.Code, r.Body.String())
	}
	if r := accept(f.standby.ID, f.standby.recipient()); r.Code != http.StatusConflict || problemCode(t, r) != "MACHINE_KEY_NOT_PENDING" {
		t.Fatalf("accepting on a machine with nothing pending: %d %s", r.Code, r.Body.String())
	}
	// keytool 风格（大写带冒号）的指纹也认
	colon, _ := colonFingerprint(fingerprint.SHA256Hex(newX))
	accepted := accept(f.primary.ID, colon)
	if accepted.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", accepted.Code, accepted.Body.String())
	}
	view := decodeBody(t, accepted)["machine"].(map[string]any)
	if view["publicKeySha256"] != fingerprint.SHA256Hex(newX) || view["ed25519PublicKeySha256"] != fingerprint.SHA256Hex(newEd) || view["pendingPublicKeySha256"] != nil || view["acceptedBy"] != "tester@example.com" {
		t.Fatalf("accepted view: %v", view)
	}

	// 构建机换钥同理（主公钥就是 Ed25519，ed25519 那一段为空串）
	_, builderNext, _ := ed25519.GenerateKey(rand.Reader)
	builderPublic := builderNext.Public().(ed25519.PublicKey)
	builderProof, _ := machinekey.SignRotation(f.builder.Ed25519, f.builder.ID, fingerprint.SHA256Hex(builderPublic), "")
	if r := f.do(http.MethodPost, "/v1/build-agent/public-key", f.builder.Token, nil, map[string]any{
		"publicKey": base64.StdEncoding.EncodeToString(builderPublic), "rotationSignature": base64.StdEncoding.EncodeToString(builderProof),
	}); r.Code != http.StatusOK || decodeBody(t, r)["pendingPublicKeySha256"] != fingerprint.SHA256Hex(builderPublic) {
		t.Fatalf("builder rotation: %d %s", r.Code, r.Body.String())
	}
	// 另一台机器登记同一把公钥：不行
	if r := f.do(http.MethodPost, "/v1/signer/public-key", f.standby.Token, nil, map[string]any{
		"x25519PublicKey": base64.StdEncoding.EncodeToString(newX), "ed25519PublicKey": base64.StdEncoding.EncodeToString(newEd),
		"rotationSignature": mustRotation(t, f.standby, newX, newEd),
	}); r.Code != http.StatusConflict || problemCode(t, r) != "MACHINE_KEY_IN_USE" {
		t.Fatalf("a key reused by another machine: %d %s", r.Code, r.Body.String())
	}

	switched := f.adminDo(http.MethodPost, "/v1/admin/platform/machines/"+f.standby.ID+"/signer-role", map[string]any{
		"signerRole": "primary", "expectedVersion": registryVersion(t, f), "reason": "promote the standby", "confirm": true,
	})
	if switched.Code != http.StatusOK {
		t.Fatalf("switch primary: %d %s", switched.Code, switched.Body.String())
	}
	roles := map[string]any{}
	for _, item := range decodeBody(t, switched)["items"].([]any) {
		entry := item.(map[string]any)
		roles[entry["id"].(string)] = entry["signerRole"]
	}
	if roles[f.standby.ID] != "primary" || roles[f.primary.ID] != "standby" || roles[f.builder.ID] != nil {
		t.Fatalf("roles after switching: %v", roles)
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/machines/"+f.builder.ID+"/signer-role", map[string]any{
		"signerRole": "primary", "expectedVersion": registryVersion(t, f), "reason": "not a signer", "confirm": true,
	}); r.Code != http.StatusBadRequest {
		t.Fatalf("a builder given a signer role: %d %s", r.Code, r.Body.String())
	}
}

func mustRotation(t *testing.T, machine gateMachine, x25519, signing []byte) string {
	t.Helper()
	proof, err := machinekey.SignRotation(machine.Ed25519, machine.ID, fingerprint.SHA256Hex(x25519), fingerprint.SHA256Hex(signing))
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(proof)
}

// 登记的不变量写不进库：两台 primary、重名、没有公钥的 active。
func TestMachineRegistryInvariants(t *testing.T) {
	builder := newGateMachine(t, machineRoleBuilder, "builder-a")
	a := newGateMachine(t, machineRoleSigner, "signer-a")
	b := newGateMachine(t, machineRoleSigner, "signer-b")
	if err := (buildMachinesDoc{Machines: []buildMachine{builder.record(""), a.record(signerRolePrimary), b.record(signerRoleStandby)}}).validate(); err != nil {
		t.Fatalf("a valid registry was refused: %v", err)
	}
	twoPrimaries := buildMachinesDoc{Machines: []buildMachine{a.record(signerRolePrimary), b.record(signerRolePrimary)}}
	if twoPrimaries.validate() == nil {
		t.Fatal("two live primaries were accepted")
	}
	revokedPrimary := b.record(signerRolePrimary)
	revokedPrimary.Status = machineStatusRevoked
	if err := (buildMachinesDoc{Machines: []buildMachine{a.record(signerRolePrimary), revokedPrimary}}).validate(); err != nil {
		t.Fatalf("a revoked former primary blocks the new one: %v", err)
	}
	clash := b.record(signerRoleStandby)
	clash.Name = a.Name
	if (buildMachinesDoc{Machines: []buildMachine{a.record(signerRolePrimary), clash}}).validate() == nil {
		t.Fatal("two live machines with the same name were accepted")
	}
	keyless := builder.record("")
	keyless.PublicKey, keyless.PublicKeySHA256 = "", ""
	if (buildMachinesDoc{Machines: []buildMachine{keyless}}).validate() == nil {
		t.Fatal("an active machine without a key was accepted")
	}
	raw, _ := json.Marshal(machineView(a.record(signerRolePrimary)))
	for _, forbidden := range []string{"tokenSha256", `"publicKey"`, `"ed25519PublicKey"`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("machineView carries %s: %s", forbidden, raw)
		}
	}
}
