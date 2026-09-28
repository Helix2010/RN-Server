package api

// iOS 签名材料的密文分发：服务端这一侧（设计 ios-signing-material-distribution-2026-09-19、
// ios-tenant-owned-signing-material-2026-09-25）。
//
// 这一组要守住两句：**服务端是快递员，不是保管员**——它存的每一份都解不开，它做的每一条检查都只为
// 帮人当场发现拿错文件；**材料按租户存**——一个租户传、删自己的材料碰不到别的租户，打包机只有带了
// 能力才拿得到按租户的清单。

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/iosmaterial"
)

// materialTeam 与 materialBundle 是 newIOSPool 给夹具租户登记的 iOS 身份：租户只能交这个 Team、这个 bundle id 的材料
const (
	materialTeam   = poolTeamA
	materialBundle = poolBundle
)

// clearStoredMaterial 清空材料表。
//
// **整表清**：ios_signing_material 是平台级的，不按租户也不按夹具隔离，而本地跑测试用的
// 是一个长期存在的库——上一个用例、上一次 go test 留下的行都会被下一个用例看见。已经踩过：
// "另一台机器看见了别人的上传 Key"，实际看见的是前一个用例留下的证书。
func clearStoredMaterial(t *testing.T, f *gateFixture) {
	t.Helper()
	if _, err := f.s.db.Exec(`DELETE FROM ios_signing_material`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`,
		platformTenantID, buildIOSMaterialConfigKey); err != nil {
		t.Fatal(err)
	}
}

// materialKeys 造两把平台密钥，并登记上去。
func materialKeys(t *testing.T, f *gateFixture) (builder, uploader *sealedboxKey) {
	t.Helper()
	builder, uploader = newSealedboxKey(t), newSealedboxKey(t)
	r := f.adminDo(http.MethodPut, "/v1/admin/platform/ios-material/recipients", map[string]any{
		"builderPublicKey": builder.pubBase64, "uploaderPublicKey": uploader.pubBase64,
		"expectedVersion": iosMaterialVersion(t, f), "reason": "register the platform keys", "confirm": true,
	})
	if r.Code != http.StatusOK {
		t.Fatalf("register recipients: %d %s", r.Code, r.Body.String())
	}
	return builder, uploader
}

type sealedboxKey struct {
	private   []byte
	pub       []byte
	pubBase64 string
}

func newSealedboxKey(t *testing.T) *sealedboxKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PublicKey().Bytes()
	return &sealedboxKey{private: key.Bytes(), pub: pub, pubBase64: base64.StdEncoding.EncodeToString(pub)}
}

func iosMaterialVersion(t *testing.T, f *gateFixture) int {
	t.Helper()
	body := decodeBody(t, f.adminDo(http.MethodGet, "/v1/admin/platform/ios-material", nil))
	version, _ := body["version"].(float64)
	return int(version)
}

func sealMaterial(t *testing.T, m iosmaterial.Material, key *sealedboxKey) []byte {
	t.Helper()
	box, err := iosmaterial.Seal(m, key.pub)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(box)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func certificateMaterial() iosmaterial.Material {
	return iosmaterial.Material{
		Kind: iosmaterial.KindCertificate, TeamID: materialTeam,
		P12Base64:   base64.StdEncoding.EncodeToString([]byte("pkcs12")),
		P12Password: "a password",
	}
}

func uploadMaterial() iosmaterial.Material {
	return iosmaterial.Material{
		Kind: iosmaterial.KindUploadKey, TeamID: materialTeam,
		IssuerID: "3223da1d-14c5-46fc-80a1-41ecfb6e3c67", KeyID: "8WQNTAY7MP",
		P8Base64: base64.StdEncoding.EncodeToString([]byte("p8")),
	}
}

// forTenant 把一份材料标成这个租户的（封出来是 v2）。
func forTenant(m iosmaterial.Material, tenant string) iosmaterial.Material {
	m.TenantID = tenant
	return m
}

// uploadMaterialBox 以这个租户的身份走租户接口传一份密文。直接调处理函数：二次验证与路由由
// TestDBTenantIOSMaterialRoutes 单独钉。
func uploadMaterialBox(t *testing.T, f *gateFixture, tenant string, raw []byte) (int, map[string]any) {
	t.Helper()
	c, recorder := testContext(t, tenant, http.MethodPost, "/v1/admin/ios/material", json.RawMessage(raw))
	f.s.uploadTenantIOSMaterial(c)
	if recorder.Body.Len() == 0 {
		return recorder.Code, nil
	}
	return recorder.Code, decodeBody(t, recorder)
}

// uploadOwn 以夹具租户的身份传一份它自己的材料，必须成功。
func uploadOwn(t *testing.T, f *gateFixture, m iosmaterial.Material, key *sealedboxKey) float64 {
	t.Helper()
	code, body := uploadMaterialBox(t, f, f.tenant, sealMaterial(t, forTenant(m, f.tenant), key))
	if code != http.StatusOK {
		t.Fatalf("upload %s: %d %v", m.Kind, code, body)
	}
	version, _ := body["version"].(float64)
	return version
}

// machineMaterial 是一台机器取到的清单；tenantLayout 决定带不带 tenant-signing-material 能力。
func machineMaterial(t *testing.T, f *gateFixture, mac gateMachine, tenantLayout bool) map[string]any {
	t.Helper()
	path := "/v1/build-agent/ios-material"
	if tenantLayout {
		path += "?capability=" + machineCapabilityTenantMaterial
	}
	r := f.do(http.MethodGet, path, mac.Token, nil, nil)
	if r.Code != http.StatusOK {
		t.Fatalf("machine material list: %d %s", r.Code, r.Body.String())
	}
	return decodeBody(t, r)
}

// profileFor 是夹具租户那个 App 的描述文件。
func profileFor(bundle string) iosmaterial.Material {
	return iosmaterial.Material{
		Kind: iosmaterial.KindProfile, TeamID: materialTeam, BundleID: bundle,
		ProfileBase64: base64.StdEncoding.EncodeToString([]byte("profile")),
	}
}

// 正路：租户传一份证书，带能力的机器在按租户的清单里看得见它，取回来的密文与传上去的逐字节相同；
// 不带能力的旧机器看不见它。
func TestDBIOSMaterialIsHandedBackByteForByte(t *testing.T) {
	f, macs := newIOSPool(t, 80, 1)
	clearStoredMaterial(t, f)
	builder, _ := materialKeys(t, f)

	first := uploadOwn(t, f, certificateMaterial(), builder)
	if first < float64(materialVersionFloor) {
		t.Fatalf("version %v is below the timestamp floor", first)
	}
	// 再传一份：只留当前这一版，版本号往上走
	if second := uploadOwn(t, f, certificateMaterial(), builder); second <= first {
		t.Fatalf("second upload got %v (first %v)", second, first)
	}

	list := machineMaterial(t, f, macs[0], true)
	items, _ := list["items"].([]any)
	if list["layout"] != "tenant" || len(items) != 1 {
		t.Fatalf("the machine sees %v: %v", list["layout"], items)
	}
	if item := items[0].(map[string]any); item["tenantId"] != f.tenant || item["legacy"] != false {
		t.Fatalf("the item must name its tenant: %v", item)
	}
	// 旧打包机拿的是按 Team 的旧行：它会把两个租户落进同一格，绝不能拿到按租户的材料
	if legacy := machineMaterial(t, f, macs[0], false); legacy["layout"] != nil || len(legacy["items"].([]any)) != 0 {
		t.Fatalf("a machine without the capability must not see tenant material: %v", legacy)
	}

	fresh := sealMaterial(t, forTenant(certificateMaterial(), f.tenant), builder)
	if code, body := uploadMaterialBox(t, f, f.tenant, fresh); code != http.StatusOK {
		t.Fatalf("third upload failed: %d %v", code, body)
	}
	got := f.do(http.MethodGet, "/v1/build-agent/ios-material/box?tenantId="+f.tenant+"&kind=certificate&teamId="+materialTeam+"&scope=",
		macs[0].Token, nil, nil)
	if got.Code != http.StatusOK {
		t.Fatalf("fetch: %d %s", got.Code, got.Body.String())
	}
	if strings.TrimSpace(got.Body.String()) != strings.TrimSpace(string(fresh)) {
		t.Fatal("the ciphertext came back changed; the server must hand it over untouched")
	}
	// 不带 tenantId 取的是按 Team 的旧行，那里没有这一份
	if r := f.do(http.MethodGet, "/v1/build-agent/ios-material/box?kind=certificate&teamId="+materialTeam+"&scope=",
		macs[0].Token, nil, nil); r.Code != http.StatusNotFound {
		t.Fatalf("the legacy slot must be empty: %d %s", r.Code, r.Body.String())
	}
	// 控制台那张总览不下发密文
	overview := f.adminDo(http.MethodGet, "/v1/admin/platform/ios-material", nil).Body.String()
	if strings.Contains(overview, `"ct"`) {
		t.Error("the admin overview hands out ciphertext; it has no reason to")
	}
}

// 租户接口的判据（设计 §3.2、§12.4）：只收 v2、租户是自己、Team 与 bundle id 是自己登记的那个、
// 自助上传不收上传 Key、加密给的是登记的公钥。每一条都是帮人当场发现传错了——真正的关在 Mac 上。
func TestDBTenantIOSMaterialUploadChecks(t *testing.T) {
	f, _ := newIOSPool(t, 81, 1)
	clearStoredMaterial(t, f)
	builder, uploader := materialKeys(t, f)
	stranger := newSealedboxKey(t)
	other := testTenant(88)
	seedBuildTenant(t, f.s, other)

	wrongTeam := certificateMaterial()
	wrongTeam.TeamID = poolTeamB
	for name, c := range map[string]struct {
		raw    []byte
		status int
		code   string
	}{
		"v1 has no tenant":        {sealMaterial(t, certificateMaterial(), builder), http.StatusBadRequest, "IOS_MATERIAL_VERSION_UNSUPPORTED"},
		"another tenant's":        {sealMaterial(t, forTenant(certificateMaterial(), other), builder), http.StatusForbidden, "IOS_MATERIAL_TENANT_MISMATCH"},
		"another team":            {sealMaterial(t, forTenant(wrongTeam, f.tenant), builder), http.StatusConflict, "IOS_MATERIAL_TEAM_MISMATCH"},
		"another app's profile":   {sealMaterial(t, forTenant(profileFor("com.someone.else"), f.tenant), builder), http.StatusConflict, "IOS_MATERIAL_BUNDLE_MISMATCH"},
		"bundle id in other case": {sealMaterial(t, forTenant(profileFor(strings.ToUpper(materialBundle)), f.tenant), builder), http.StatusConflict, "IOS_MATERIAL_BUNDLE_MISMATCH"},
		"an unregistered key":     {sealMaterial(t, forTenant(certificateMaterial(), f.tenant), stranger), http.StatusConflict, "IOS_MATERIAL_RECIPIENT_UNKNOWN"},
		"junk":                    {[]byte(`{"v":2}`), http.StatusBadRequest, "INVALID_IOS_MATERIAL"},
	} {
		code, body := uploadMaterialBox(t, f, f.tenant, c.raw)
		if code != c.status || body["code"] != c.code {
			t.Errorf("%s: %d %v, want %d %s", name, code, body, c.status, c.code)
		}
	}
	// 描述文件的 bundle id 原样对得上就收
	uploadOwn(t, f, profileFor(materialBundle), builder)

	// 自助上传不收上传 Key：平台不持有能替租户上传的 Key
	setIOSDelivery(t, f, f.tenant, iosDeliveryIPA)
	code, body := uploadMaterialBox(t, f, f.tenant, sealMaterial(t, forTenant(uploadMaterial(), f.tenant), uploader))
	if code != http.StatusConflict || body["code"] != "IOS_DELIVERY_SELF_UPLOAD" {
		t.Fatalf("a self-upload tenant's upload key was accepted: %d %v", code, body)
	}
	setIOSDelivery(t, f, f.tenant, iosDeliveryTestFlight)
	uploadOwn(t, f, uploadMaterial(), uploader)

	// 没登记 iOS 身份的租户什么都交不了
	if _, err := f.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, f.tenant, releaseIOSIdentityConfigKey); err != nil {
		t.Fatal(err)
	}
	code, body = uploadMaterialBox(t, f, f.tenant, sealMaterial(t, forTenant(certificateMaterial(), f.tenant), builder))
	if code != http.StatusConflict || body["code"] != "IOS_IDENTITY_REQUIRED" {
		t.Fatalf("a tenant without an iOS identity uploaded: %d %v", code, body)
	}
}

// 同一个 Team 的两个租户各交各的：一个租户换、删自己的证书，另一个租户那一份原样不动（设计 §3.1）。
func TestDBTenantIOSMaterialDoesNotTouchAnotherTenant(t *testing.T) {
	f, macs := newIOSPool(t, 89, 1)
	clearStoredMaterial(t, f)
	builder, _ := materialKeys(t, f)
	other := testTenant(90)
	seedBuildTenant(t, f.s, other)
	raw, _ := json.Marshal(iosReleaseIdentity{AppleTeamID: materialTeam, BundleID: "com.pool.other"})
	if _, err := f.db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,'test',UTC_TIMESTAMP(3))`,
		other, releaseIOSIdentityConfigKey, raw); err != nil {
		t.Fatal(err)
	}
	theirs := sealMaterial(t, forTenant(certificateMaterial(), other), builder)
	if code, body := uploadMaterialBox(t, f, other, theirs); code != http.StatusOK {
		t.Fatalf("the other tenant's upload: %d %v", code, body)
	}
	uploadOwn(t, f, certificateMaterial(), builder)
	remove := func(tenant string) *httptest.ResponseRecorder {
		c, recorder := testContext(t, tenant, http.MethodPost, "/v1/admin/ios/material/remove", map[string]any{
			"kind": iosmaterial.KindCertificate, "teamId": materialTeam, "scope": "", "reason": "rotate the certificate", "confirm": true,
		})
		f.s.removeTenantIOSMaterial(c)
		return recorder
	}
	if r := remove(f.tenant); r.Code != http.StatusOK {
		t.Fatalf("remove own: %d %s", r.Code, r.Body.String())
	}
	if r := remove(f.tenant); r.Code != http.StatusNotFound {
		t.Fatalf("removing twice: %d %s", r.Code, r.Body.String())
	}
	got := f.do(http.MethodGet, "/v1/build-agent/ios-material/box?tenantId="+other+"&kind=certificate&teamId="+materialTeam+"&scope=",
		macs[0].Token, nil, nil)
	if got.Code != http.StatusOK || strings.TrimSpace(got.Body.String()) != string(theirs) {
		t.Fatalf("the other tenant's certificate must survive: %d %s", got.Code, got.Body.String())
	}
	items := machineMaterial(t, f, macs[0], true)["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["tenantId"] != other {
		t.Fatalf("only the other tenant's certificate is left: %v", items)
	}
}

// 角色不能混：上传 Key 必须加密给上传那把。加密给构建那把的话，Mac 上解它的是
// _rnuploader，而那个账户没有构建账户的私钥。
func TestDBIOSMaterialKeepsTheTwoRolesApart(t *testing.T) {
	f, _ := newIOSPool(t, 82, 1)
	clearStoredMaterial(t, f)
	builder, uploader := materialKeys(t, f)

	wrong := uploadMaterial()
	wrong.Purpose = iosmaterial.PurposeBuilder
	if _, err := iosmaterial.Seal(wrong, builder.pub); err == nil {
		t.Fatal("iosmaterial sealed an upload key under the builder purpose")
	}
	code, body := uploadMaterialBox(t, f, f.tenant, sealMaterial(t, forTenant(uploadMaterial(), f.tenant), builder))
	if code != http.StatusConflict || body["code"] != "IOS_MATERIAL_RECIPIENT_UNKNOWN" {
		t.Fatalf("an upload key sealed to the builder key was accepted: %d %v", code, body)
	}
	// 正确的那一份收得下
	uploadOwn(t, f, uploadMaterial(), uploader)
}

// 上传 Key 与证书一样是**这个租户一份**：每台 Mac 都看得见、都取得走。
//
// 它起初按机器分（每台一把）。那条策略挡不住它要挡的事——证书本来就全机共用，丢一台 Mac
// 就得吊销证书、重签、全机重发，那一刻所有 Mac 都停了——代价却是把"平台有几台打包机"
// 漏给租户（ASC Key 只能在租户自己的 Apple 账号里建）。设计 §5 记了这次调整。
func TestDBIOSUploadKeyGoesToEveryMac(t *testing.T) {
	f, macs := newIOSPool(t, 83, 2)
	clearStoredMaterial(t, f)
	builder, uploader := materialKeys(t, f)
	uploadOwn(t, f, certificateMaterial(), builder)
	uploadOwn(t, f, uploadMaterial(), uploader)

	for name, mac := range map[string]gateMachine{"first": macs[0], "second": macs[1]} {
		items, _ := machineMaterial(t, f, mac, true)["items"].([]any)
		kinds := map[string]bool{}
		for _, item := range items {
			entry, _ := item.(map[string]any)
			kind, _ := entry["kind"].(string)
			kinds[kind] = true
		}
		if !kinds["certificate"] || !kinds["upload-key"] {
			t.Errorf("%s does not see both kinds: %v", name, items)
		}
		if r := f.do(http.MethodGet, "/v1/build-agent/ios-material/box?tenantId="+f.tenant+"&kind=upload-key&teamId="+materialTeam+"&scope=",
			mac.Token, nil, nil); r.Code != http.StatusOK {
			t.Errorf("%s could not fetch the upload key: %d %s", name, r.Code, r.Body.String())
		}
	}
}

// 换平台公钥 = 已经存着的密文全部作废（新私钥解不开旧密文）。有多少份会失效必须当场说，
// 不能让人换完之后靠"机器怎么一直取不到材料"去发现。
func TestDBIOSMaterialSaysHowMuchAKeyChangeOrphans(t *testing.T) {
	f, _ := newIOSPool(t, 84, 1)
	clearStoredMaterial(t, f)
	builder, uploader := materialKeys(t, f)
	uploadOwn(t, f, certificateMaterial(), builder)
	uploadOwn(t, f, uploadMaterial(), uploader)

	next := newSealedboxKey(t)
	r := f.adminDo(http.MethodPut, "/v1/admin/platform/ios-material/recipients", map[string]any{
		"builderPublicKey": next.pubBase64, "uploaderPublicKey": uploader.pubBase64,
		"expectedVersion": iosMaterialVersion(t, f), "reason": "rotate the builder key", "confirm": true,
	})
	if r.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", r.Code, r.Body.String())
	}
	// 证书那一份作废了，上传 Key 那一份没有（它那把没换）
	if got := decodeBody(t, r)["orphanedMaterial"]; got != float64(1) {
		t.Fatalf("orphanedMaterial = %v, want 1", got)
	}
}

// 两把不能是同一把：那样拿到构建账户就同时拿到了上传能力。
func TestDBIOSMaterialRefusesOneKeyForBothRoles(t *testing.T) {
	f, _ := newIOSPool(t, 85, 1)
	clearStoredMaterial(t, f)
	same := newSealedboxKey(t)
	r := f.adminDo(http.MethodPut, "/v1/admin/platform/ios-material/recipients", map[string]any{
		"builderPublicKey": same.pubBase64, "uploaderPublicKey": same.pubBase64,
		"expectedVersion": iosMaterialVersion(t, f), "reason": "one key for both", "confirm": true,
	})
	if r.Code != http.StatusBadRequest {
		t.Fatalf("one key was accepted for both roles: %d %s", r.Code, r.Body.String())
	}
}

// 平台的紧急删除（设计 §3.4）：要带租户，删完机器的清单里就没有它了，审计记在那个租户名下，
// 租户页上看得见「平台删了什么、为什么」。平台不代交：上传口已经没有了。
func TestDBIOSMaterialEmergencyRemoval(t *testing.T) {
	f, macs := newIOSPool(t, 86, 1)
	clearStoredMaterial(t, f)
	builder, _ := materialKeys(t, f)
	uploadOwn(t, f, certificateMaterial(), builder)
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/ios-material",
		json.RawMessage(sealMaterial(t, forTenant(certificateMaterial(), f.tenant), builder))); r.Code != http.StatusNotFound {
		t.Fatalf("the platform must not be able to upload for a tenant: %d %s", r.Code, r.Body.String())
	}
	remove := map[string]any{"kind": "certificate", "teamId": materialTeam, "scope": "",
		"reason": "the certificate leaked", "confirm": true}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/ios-material/remove", remove); r.Code != http.StatusBadRequest {
		t.Fatalf("an emergency removal without a tenant: %d %s", r.Code, r.Body.String())
	}
	remove["tenantId"] = f.tenant
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/ios-material/remove", remove); r.Code != http.StatusOK {
		t.Fatalf("remove: %d %s", r.Code, r.Body.String())
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/ios-material/remove", remove); r.Code != http.StatusNotFound {
		t.Fatalf("removing twice: %d %s", r.Code, r.Body.String())
	}
	if items, _ := machineMaterial(t, f, macs[0], true)["items"].([]any); len(items) != 0 {
		t.Fatalf("a removed material is still listed: %v", items)
	}
	body := tenantMaterialView(t, f)
	removals, _ := body["removals"].([]any)
	if len(removals) == 0 {
		t.Fatalf("the tenant does not see the platform's removal: %v", body)
	}
	if latest := removals[0].(map[string]any); latest["kind"] != "certificate" || latest["reason"] != "the certificate leaked" || latest["actor"] != nil {
		t.Fatalf("the removal notice: %v", latest)
	}
}

// materialVersionFloor 是 2026-09-25 的毫秒时间戳：新传的材料版本号不会比它小。
var materialVersionFloor = time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC).UnixMilli()

// 删掉再传，版本号不能倒回去：打包机按「本机版本 >= 清单版本」跳过，版本号一旦重来，
// 装过旧证书的机器就永远装不上新的。2026-09-25 之前每格从 1 数起、删行即重来，正是这样。
func TestDBIOSMaterialVersionSurvivesRemoval(t *testing.T) {
	f, _ := newIOSPool(t, 87, 1)
	clearStoredMaterial(t, f)
	builder, _ := materialKeys(t, f)
	before := uploadOwn(t, f, certificateMaterial(), builder)
	remove := map[string]any{"tenantId": f.tenant, "kind": "certificate", "teamId": materialTeam, "scope": "",
		"expectedVersion": int64(before), "reason": "replace the certificate", "confirm": true}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/ios-material/remove", remove); r.Code != http.StatusOK {
		t.Fatalf("remove: %d %s", r.Code, r.Body.String())
	}
	code, body := uploadMaterialBox(t, f, f.tenant, sealMaterial(t, forTenant(certificateMaterial(), f.tenant), builder))
	if after, _ := body["version"].(float64); code != http.StatusOK || after <= before {
		t.Fatalf("the re-uploaded material got version %v, not above the removed %v; machines that installed the old one would skip it", after, before)
	}
}

func TestNextIOSMaterialVersionNeverGoesBack(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	if got := nextIOSMaterialVersion(0, now); got != now.UnixMilli() {
		t.Errorf("a fresh slot takes the timestamp: %d", got)
	}
	if got := nextIOSMaterialVersion(3, now); got != now.UnixMilli() {
		t.Errorf("an old small version is overtaken by the timestamp: %d", got)
	}
	// 同一毫秒里连传两次、或者时钟往回拨：仍然比上一版大
	if got := nextIOSMaterialVersion(now.UnixMilli(), now); got != now.UnixMilli()+1 {
		t.Errorf("the same millisecond: %d", got)
	}
	if got := nextIOSMaterialVersion(now.UnixMilli()+5000, now); got != now.UnixMilli()+5001 {
		t.Errorf("a clock that went back: %d", got)
	}
}

func (k *sealedboxKey) pubSHA() string {
	box, _ := iosmaterial.Seal(certificateMaterial(), k.pub)
	return box.RecipientSHA256
}
