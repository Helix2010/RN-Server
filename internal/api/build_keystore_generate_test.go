package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/androidkeystore"
	"github.com/Helix2010/RN-Server/internal/buildkeystore"
	"github.com/Helix2010/RN-Server/internal/secretbox"
)

func generateRequest(pkg string) map[string]any {
	return map[string]any{
		"packageName": pkg, "commonName": "AnyFun Wallet", "organization": "AnyFun", "country": "SG",
		"keyAlias": "anyfun-release", "keySize": 2048, "validityYears": 30,
		"expectedVersion": 0, "releaseIdentityExpectedVersion": 0,
		"reason": "new tenant setup", "confirm": true,
	}
}

func signingServer(t *testing.T) (*server, []byte) {
	t.Helper()
	// 32 字节的测试主密钥。外层加密用它，内层那个盒子它打不开——这个测试要证明的
	// 正是这一点
	box, err := secretbox.New(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	if err != nil {
		t.Fatalf("secretbox: %v", err)
	}
	s := &server{db: openTestDB(t), secrets: box}
	// 生成出来的密钥要加密给打包机的公钥。没登记的话生成会被拒——这本身也是一条
	// 用例（见 TestDBGenerateRefusesWhenNoBuildAgentKeyIsRegistered）
	agentPrivate, recipient, err := buildkeystore.NewAgentKey()
	if err != nil {
		t.Fatalf("agent key: %v", err)
	}
	if err := s.saveBuildAgentKey(context.Background(), buildAgentKeyRecord{
		Current: recipient, Agent: "test-builder", RegisteredAt: iso(time.Now().UTC()),
	}, "tester"); err != nil {
		t.Fatalf("register agent key: %v", err)
	}
	return s, agentPrivate
}

// 生成这条路径要一次交付三样东西，而且必须一致：打包机拿到的盒子、发布身份 pin 的
// 指纹、还给管理员备份的那个文件。任何两样对不上，表现都是"构建成功但产物被拒"或者
// "包签出来了但装不上去"，而报错都指不到根因。
func TestDBGenerateBuildKeystorePinsTheFingerprintItActuallyGenerated(t *testing.T) {
	s, agentPrivate := signingServer(t)
	tenant := testTenant(1)

	c, recorder := testContext(t, tenant, http.MethodPost, "/v1/admin/build-keystore/generate", generateRequest("com.anyfun.wallet"))
	s.generateBuildKeystore(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("generate failed: %d %s", recorder.Code, recorder.Body.String())
	}
	body := decodeBody(t, recorder)
	signer, _ := body["signerSha256"].(string)
	storePassword, _ := body["storePassword"].(string)
	encoded, _ := body["keystoreBase64"].(string)
	if len(signer) != 64 || storePassword == "" || encoded == "" {
		t.Fatalf("response is missing the one-time material: %v", body)
	}
	if body["version"] != float64(1) || body["releaseIdentityVersion"] != float64(1) {
		t.Fatalf("versions = %v / %v", body["version"], body["releaseIdentityVersion"])
	}
	if body["packageName"] != "com.anyfun.wallet" || body["keyAlias"] != "anyfun-release" {
		t.Fatalf("identity fields = %v", body)
	}

	// 1. 发布身份要 pin 到刚生成的那张证书上，而不是留空等人来填
	record, err := s.androidReleaseIdentityRecord(t.Context(), tenant)
	if err != nil || record == nil {
		t.Fatalf("release identity not written: %v", err)
	}
	if record.Value.SignerSHA256 != signer || record.Value.PackageName != "com.anyfun.wallet" {
		t.Fatalf("pinned %+v, generated %s", record.Value, signer)
	}

	// 2. 打包机拿到的盒子里必须是同一把密钥。这是"构建出来的包能不能入库"的全部依据。
	sealedJSON, alias, err := s.sealedBuildKeystoreFor(t.Context(), tenant)
	if err != nil || len(sealedJSON) == 0 {
		t.Fatalf("sealed keystore not readable by the dispatch path: %v", err)
	}
	if alias != "anyfun-release" {
		t.Fatalf("alias %q", alias)
	}
	var sealed buildkeystore.Sealed
	if err := json.Unmarshal(sealedJSON, &sealed); err != nil {
		t.Fatalf("sealed box is not the expected shape: %v", err)
	}
	// 服务端自己打不开它刚存下去的盒子——它只有公钥。这正是签名密钥可以放进数据库
	// 的那条论证，换成公钥之后必须仍然成立
	if _, err := buildkeystore.OpenWith(sealed, nil); err == nil {
		t.Fatal("没有私钥也解开了")
	}
	otherPrivate, _, _ := buildkeystore.NewAgentKey()
	if _, err := buildkeystore.OpenWith(sealed, otherPrivate); err == nil {
		t.Fatal("另一台打包机的私钥解开了")
	}
	bundle, err := buildkeystore.OpenWith(sealed, agentPrivate)
	if err != nil {
		t.Fatalf("the build machine could not open the box: %v", err)
	}
	fromBox, err := base64.StdEncoding.DecodeString(bundle.KeystoreBase64)
	if err != nil {
		t.Fatalf("the box does not carry a keystore: %v", err)
	}
	inBox, err := androidkeystore.CertificateSHA256(fromBox, bundle.StorePassword)
	if err != nil {
		t.Fatalf("the keystore in the box cannot be opened with the password in the box: %v", err)
	}
	if inBox != signer {
		t.Fatalf("the build machine would sign with %s but %s is pinned", inBox, signer)
	}

	// 3. 还给管理员备份的那份，要能用响应里那个口令打开——它是唯一一份
	backup, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("keystoreBase64 is not base64: %v", err)
	}
	backupSigner, err := androidkeystore.CertificateSHA256(backup, storePassword)
	if err != nil {
		t.Fatalf("the downloaded backup does not open with the returned password: %v", err)
	}
	if backupSigner != signer {
		t.Fatalf("the backup holds %s, not the key we pinned (%s)", backupSigner, signer)
	}

	if keytool := findKeytoolForTest(); keytool != "" {
		path := filepath.Join(t.TempDir(), "release.p12")
		if err := os.WriteFile(path, backup, 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command(keytool, "-list", "-v", "-keystore", path, "-storepass", storePassword).CombinedOutput()
		if err != nil {
			t.Fatalf("Gradle's reader (keytool) refused the generated keystore: %v\n%s", err, output)
		}
		// Gradle 拿 keyAlias 去找条目，找不到就在构建的最后一步失败
		if !strings.Contains(string(output), "Alias name: anyfun-release") {
			t.Fatalf("the alias is not the one we configured:\n%s", output)
		}
	}
}

// 两个乐观锁分别管两条记录，任何一条过期都要在生成之前就说清楚——生成一把密钥
// 要几秒，跑完再报冲突只会让人重来一次。
func TestDBGenerateBuildKeystoreRefusesStaleVersions(t *testing.T) {
	s, _ := signingServer(t)
	tenant := testTenant(2)
	c, recorder := testContext(t, tenant, http.MethodPost, "/v1/admin/build-keystore/generate", generateRequest("com.anyfun.wallet"))
	s.generateBuildKeystore(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("first generate failed: %d %s", recorder.Code, recorder.Body.String())
	}

	// 现在两条记录都是 v1，再拿 expectedVersion=0 提交就是"你那份旧了"
	stale := generateRequest("com.anyfun.wallet")
	c, recorder = testContext(t, tenant, http.MethodPost, "/v1/admin/build-keystore/generate", stale)
	s.generateBuildKeystore(c)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("stale keystore version got %d: %s", recorder.Code, recorder.Body.String())
	}
	if code, _ := decodeBody(t, recorder)["code"].(string); code != "STALE_BUILD_KEYSTORE" {
		t.Fatalf("code = %s", code)
	}

	// keystore 版本对上、发布身份版本没对上，也要拦住：那说明有人刚改过 pin
	halfStale := generateRequest("com.anyfun.wallet")
	halfStale["expectedVersion"] = 1
	c, recorder = testContext(t, tenant, http.MethodPost, "/v1/admin/build-keystore/generate", halfStale)
	s.generateBuildKeystore(c)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("stale release identity version got %d: %s", recorder.Code, recorder.Body.String())
	}
	if code, _ := decodeBody(t, recorder)["code"].(string); code != "STALE_RELEASE_IDENTITY" {
		t.Fatalf("code = %s", code)
	}
}

func TestDBGenerateBuildKeystoreRejectsUnusableInput(t *testing.T) {
	s, _ := signingServer(t)
	for name, mutate := range map[string]struct {
		change func(map[string]any)
		code   string
	}{
		"not an application id":        {func(b map[string]any) { b["packageName"] = "wallet" }, "INVALID_RELEASE_IDENTITY"},
		"alias Gradle cannot use":      {func(b map[string]any) { b["keyAlias"] = "my alias" }, "INVALID_KEYSTORE_PARAMETERS"},
		"certificate expires too soon": {func(b map[string]any) { b["validityYears"] = 2 }, "INVALID_KEYSTORE_PARAMETERS"},
		"no reason":                    {func(b map[string]any) { b["reason"] = "" }, "INVALID_BUILD_KEYSTORE"},
	} {
		t.Run(name, func(t *testing.T) {
			body := generateRequest("com.anyfun.wallet")
			mutate.change(body)
			c, recorder := testContext(t, testTenant(3), http.MethodPost, "/v1/admin/build-keystore/generate", body)
			s.generateBuildKeystore(c)
			if recorder.Code < 400 || recorder.Code >= 500 {
				t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
			}
			if code, _ := decodeBody(t, recorder)["code"].(string); code != mutate.code {
				t.Fatalf("code = %s, want %s (%s)", code, mutate.code, recorder.Body.String())
			}
		})
	}
}

func findKeytoolForTest() string {
	if path, err := exec.LookPath("keytool"); err == nil {
		return path
	}
	matches, _ := filepath.Glob("/usr/lib/jvm/*/bin/keytool")
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}

// 读和写回的是同一个资源，管理端两处用同一个 schema 解析。少两个键的表现是：
// 服务端明明存好了，界面却报"上传失败"，而错误说的是字段类型不对——上传这条路
// 就是因为这个从来没有成功过一次。
func TestDBBuildKeystoreReadAndWriteReturnTheSameShape(t *testing.T) {
	s, _ := signingServer(t)
	tenant := testTenant(4)

	c, recorder := testContext(t, tenant, http.MethodPut, "/v1/admin/build-keystore", map[string]any{
		"sealed": map[string]any{
			"v": 1, "kdf": "scrypt", "n": 65536, "r": 8, "p": 1,
			"salt": "c2FsdA==", "nonce": "bm9uY2U=", "ciphertext": "Y2lwaGVy",
		},
		"keyAlias": "anyfun", "keystoreSha256": strings.Repeat("a", 64),
		"expectedVersion": 0, "reason": "upload sealed keystore", "confirm": true,
	})
	s.saveBuildKeystore(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", recorder.Code, recorder.Body.String())
	}
	written := decodeBody(t, recorder)

	c, recorder = testContext(t, tenant, http.MethodGet, "/v1/admin/build-keystore", nil)
	s.getBuildKeystore(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("read failed: %d %s", recorder.Code, recorder.Body.String())
	}
	read := decodeBody(t, recorder)

	for key := range read {
		if _, ok := written[key]; !ok {
			t.Fatalf("the write response is missing %q, which every reader of this resource expects", key)
		}
	}
	if written["keyAlias"] != read["keyAlias"] || written["version"] != read["version"] {
		t.Fatalf("write said %v, read says %v", written, read)
	}
}
