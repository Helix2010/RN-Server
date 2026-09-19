package api

// iOS 签名材料的密文分发：服务端这一侧（设计 ios-signing-material-distribution-2026-09-19）。
//
// 这一组要守住的只有一句：**服务端是快递员，不是保管员**。它存的每一份都解不开，它做的
// 每一条检查都只为帮运维当场发现拿错文件——传错了当场报错，好过等一台 Mac 取回去解不开。

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/signing/iosmaterial"
)

const materialTeam = "J4JDFC8LCC"

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

func uploadMaterial(machineID string) iosmaterial.Material {
	return iosmaterial.Material{
		Kind: iosmaterial.KindUploadKey, TeamID: materialTeam, MachineID: machineID,
		IssuerID: "3223da1d-14c5-46fc-80a1-41ecfb6e3c67", KeyID: "8WQNTAY7MP",
		P8Base64: base64.StdEncoding.EncodeToString([]byte("p8")),
	}
}

func uploadMaterialBox(t *testing.T, f *gateFixture, raw []byte) (int, map[string]any) {
	t.Helper()
	r := f.adminDo(http.MethodPost, "/v1/admin/platform/ios-material", json.RawMessage(raw))
	if r.Body.Len() == 0 {
		return r.Code, nil
	}
	return r.Code, decodeBody(t, r)
}

// 正路：传一份证书，机器在自己的清单里看得见它，取回来的密文与传上去的逐字节相同。
func TestDBIOSMaterialIsHandedBackByteForByte(t *testing.T) {
	f, macs := newIOSPool(t, 80, 1)
	clearStoredMaterial(t, f)
	builder, _ := materialKeys(t, f)
	raw := sealMaterial(t, certificateMaterial(), builder)

	if code, body := uploadMaterialBox(t, f, raw); code != http.StatusOK || body["version"] != float64(1) {
		t.Fatalf("upload: %d %v", code, body)
	}
	// 再传一份：只留当前这一版，版本号往上走
	if code, body := uploadMaterialBox(t, f, sealMaterial(t, certificateMaterial(), builder)); code != http.StatusOK || body["version"] != float64(2) {
		t.Fatalf("second upload: %d %v", code, body)
	}

	list := decodeBody(t, f.do(http.MethodGet, "/v1/build-agent/ios-material", macs[0].Token, nil, nil))
	items, _ := list["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("the machine sees %d items: %v", len(items), items)
	}

	fresh := sealMaterial(t, certificateMaterial(), builder)
	if code, _ := uploadMaterialBox(t, f, fresh); code != http.StatusOK {
		t.Fatal("third upload failed")
	}
	got := f.do(http.MethodGet, "/v1/build-agent/ios-material/box?kind=certificate&teamId="+materialTeam+"&scope=",
		macs[0].Token, nil, nil)
	if got.Code != http.StatusOK {
		t.Fatalf("fetch: %d %s", got.Code, got.Body.String())
	}
	if strings.TrimSpace(got.Body.String()) != strings.TrimSpace(string(fresh)) {
		t.Fatal("the ciphertext came back changed; the server must hand it over untouched")
	}
	// 控制台那张总览不下发密文
	overview := f.adminDo(http.MethodGet, "/v1/admin/platform/ios-material", nil).Body.String()
	if strings.Contains(overview, `"ct"`) {
		t.Error("the admin overview hands out ciphertext; it has no reason to")
	}
}

// 加密给一把没人持有的公钥 = 这份材料永远不会被解开。当场拒，别等机器取回去。
func TestDBIOSMaterialRefusesAnUnknownRecipient(t *testing.T) {
	f, _ := newIOSPool(t, 81, 1)
	clearStoredMaterial(t, f)
	builder, _ := materialKeys(t, f)
	stranger := newSealedboxKey(t)

	code, body := uploadMaterialBox(t, f, sealMaterial(t, certificateMaterial(), stranger))
	if code != http.StatusConflict || body["code"] != "IOS_MATERIAL_RECIPIENT_UNKNOWN" {
		t.Fatalf("a box for an unregistered key was accepted: %d %v", code, body)
	}
	if detail, _ := body["detail"].(string); !strings.Contains(detail, builder.pubSHA()) {
		t.Errorf("the refusal does not say which key is registered: %q", detail)
	}
}

// 角色不能混：上传 Key 必须加密给上传那把。加密给构建那把的话，Mac 上解它的是
// _rnuploader，而那个账户没有构建账户的私钥。
func TestDBIOSMaterialKeepsTheTwoRolesApart(t *testing.T) {
	f, macs := newIOSPool(t, 82, 1)
	clearStoredMaterial(t, f)
	builder, uploader := materialKeys(t, f)

	wrong := uploadMaterial(macs[0].ID)
	wrong.Purpose = iosmaterial.PurposeBuilder
	if _, err := iosmaterial.Seal(wrong, builder.pub); err == nil {
		t.Fatal("iosmaterial sealed an upload key under the builder purpose")
	}
	// 正确的那一份收得下
	if code, body := uploadMaterialBox(t, f, sealMaterial(t, uploadMaterial(macs[0].ID), uploader)); code != http.StatusOK {
		t.Fatalf("a correctly addressed upload key was refused: %d %v", code, body)
	}
}

// 上传 Key 是发给某一台机器的：不在登记里的机器不收，别的机器也取不走。
func TestDBIOSUploadKeyBelongsToOneMachine(t *testing.T) {
	f, macs := newIOSPool(t, 83, 2)
	clearStoredMaterial(t, f)
	builder, uploader := materialKeys(t, f)
	// 先放一份**全机共用**的证书：两台都该看见它。少了它，"清单按机器过滤"这件事就只剩
	// "两台都看不见"一种可能，过滤写错了也测不出来
	if code, _ := uploadMaterialBox(t, f, sealMaterial(t, certificateMaterial(), builder)); code != http.StatusOK {
		t.Fatal("upload certificate failed")
	}

	if code, body := uploadMaterialBox(t, f, sealMaterial(t, uploadMaterial("mch_nobody"), uploader)); code != http.StatusConflict ||
		body["code"] != "IOS_MATERIAL_MACHINE_UNKNOWN" {
		t.Fatalf("an upload key for an unknown machine was accepted: %d %v", code, body)
	}
	if code, _ := uploadMaterialBox(t, f, sealMaterial(t, uploadMaterial(macs[0].ID), uploader)); code != http.StatusOK {
		t.Fatal("upload for a real machine failed")
	}

	// 第二台机器：清单里看不见，直接取也取不走
	for name, mac := range map[string]gateMachine{"owner": macs[0], "other": macs[1]} {
		list := decodeBody(t, f.do(http.MethodGet, "/v1/build-agent/ios-material", mac.Token, nil, nil))
		items, _ := list["items"].([]any)
		kinds := map[string]bool{}
		for _, item := range items {
			entry, _ := item.(map[string]any)
			kind, _ := entry["kind"].(string)
			kinds[kind] = true
		}
		if !kinds["certificate"] {
			t.Errorf("%s does not see the shared certificate: %v", name, items)
		}
		if got := kinds["upload-key"]; got != (name == "owner") {
			t.Errorf("%s sees upload-key = %v; an upload key belongs to exactly one machine: %v", name, got, items)
		}
	}
	r := f.do(http.MethodGet, "/v1/build-agent/ios-material/box?kind=upload-key&teamId="+materialTeam+"&scope="+macs[0].ID,
		macs[1].Token, nil, nil)
	if r.Code != http.StatusForbidden {
		t.Fatalf("another machine fetched an upload key that is not its own: %d %s", r.Code, r.Body.String())
	}
	// 自己的那一份取得走
	if r := f.do(http.MethodGet, "/v1/build-agent/ios-material/box?kind=upload-key&teamId="+materialTeam+"&scope="+macs[0].ID,
		macs[0].Token, nil, nil); r.Code != http.StatusOK {
		t.Fatalf("a machine could not fetch its own upload key: %d %s", r.Code, r.Body.String())
	}
}

// 换平台公钥 = 已经存着的密文全部作废（新私钥解不开旧密文）。有多少份会失效必须当场说，
// 不能让人换完之后靠"机器怎么一直取不到材料"去发现。
func TestDBIOSMaterialSaysHowMuchAKeyChangeOrphans(t *testing.T) {
	f, macs := newIOSPool(t, 84, 1)
	clearStoredMaterial(t, f)
	builder, uploader := materialKeys(t, f)
	if code, _ := uploadMaterialBox(t, f, sealMaterial(t, certificateMaterial(), builder)); code != http.StatusOK {
		t.Fatal("upload certificate failed")
	}
	if code, _ := uploadMaterialBox(t, f, sealMaterial(t, uploadMaterial(macs[0].ID), uploader)); code != http.StatusOK {
		t.Fatal("upload key failed")
	}

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

// 删一格之后机器的清单里就没有它了。
func TestDBIOSMaterialRemoval(t *testing.T) {
	f, macs := newIOSPool(t, 86, 1)
	clearStoredMaterial(t, f)
	builder, _ := materialKeys(t, f)
	if code, _ := uploadMaterialBox(t, f, sealMaterial(t, certificateMaterial(), builder)); code != http.StatusOK {
		t.Fatal("upload failed")
	}
	remove := map[string]any{"kind": "certificate", "teamId": materialTeam, "scope": "",
		"reason": "the certificate was revoked at Apple", "confirm": true}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/ios-material/remove", remove); r.Code != http.StatusOK {
		t.Fatalf("remove: %d %s", r.Code, r.Body.String())
	}
	if r := f.adminDo(http.MethodPost, "/v1/admin/platform/ios-material/remove", remove); r.Code != http.StatusNotFound {
		t.Fatalf("removing twice: %d %s", r.Code, r.Body.String())
	}
	list := decodeBody(t, f.do(http.MethodGet, "/v1/build-agent/ios-material", macs[0].Token, nil, nil))
	if items, _ := list["items"].([]any); len(items) != 0 {
		t.Fatalf("a removed material is still listed: %v", items)
	}
}

func (k *sealedboxKey) pubSHA() string {
	box, _ := iosmaterial.Seal(certificateMaterial(), k.pub)
	return box.RecipientSHA256
}
