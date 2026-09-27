package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/pushcreds"
	"github.com/Helix2010/RN-Server/internal/secretbox"
	"github.com/gin-gonic/gin"
)

// apnsServer 与 pushServer 同构：主密钥齐了，探活换成本地桩。
//
// 探活之所以必须能替换：保存这条路**真的**会往 Apple 发一条推送（那正是这个
// 设计的重点，见 pushcreds.VerifyAPNs），测试不该出网。
func apnsServer(t *testing.T) *server {
	t.Helper()
	box, err := secretbox.New(base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return &server{
		db: openTestDB(t), secrets: box, cfg: config.Config{Environment: "test", MySQLQueryTimeout: 10},
		verifyAPNs: func(context.Context, pushcreds.APNs, []byte, string) error { return nil },
	}
}

func apnsAuthKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// seedIOSIdentity 直接写 release.ios，绕开那一页的其它必填项。
func seedIOSIdentity(t *testing.T, s *server, tenant, bundleID string) {
	t.Helper()
	value, _ := json.Marshal(map[string]string{"appleTeamId": "ABCDE12345", "bundleId": bundleID})
	if _, err := s.db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
		VALUES(?,'release.ios',?,1,'test',UTC_TIMESTAMP(3)) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)`,
		tenant, value); err != nil {
		t.Fatal(err)
	}
}

func putAPNs(t *testing.T, s *server, tenant, authKey string, expectedVersion, want int) map[string]any {
	t.Helper()
	c, recorder := testContext(t, tenant, "PUT", "/v1/admin/push/credentials/apns",
		map[string]any{"authKeyP8": authKey, "teamId": "ABCDE12345", "keyId": "XYZ9876543",
			"expectedVersion": expectedVersion, "reason": "配置 iOS 推送", "confirm": true})
	c.Set("actorId", "tester")
	s.updatePushCredentialsAPNs(c)
	if recorder.Code != want {
		t.Fatalf("状态码 %d，期望 %d：%s", recorder.Code, want, recorder.Body.String())
	}
	return decodeBody(t, recorder)
}

// 这一条钉住设计 §2.2：APNs 的 topic 取自 release.ios 的 bundleId，不在
// push.apns 里存第二份。没有 bundle id 就没有能收推送的 App，所以直接拦下，
// 而不是存一份没法验证、也发不出去的凭据。
func TestDBAPNsRequiresIOSBundleID(t *testing.T) {
	s := apnsServer(t)
	tenant := testTenant(100)
	putAPNs(t, s, tenant, apnsAuthKey(t), 0, http.StatusPreconditionFailed)

	seedIOSIdentity(t, s, tenant, "com.example.wallet")
	view := putAPNs(t, s, tenant, apnsAuthKey(t), 0, http.StatusOK)

	apns, _ := view["apns"].(map[string]any)
	if apns["configured"] != true {
		t.Fatalf("配好之后应当是 configured：%v", apns)
	}
	if apns["topic"] != "com.example.wallet" {
		t.Fatalf("topic 应当来自 release.ios：%v", apns["topic"])
	}
}

// .p8 不经任何接口返回。审计和视图里只留 teamId 和 keyId 的前几位。
func TestDBAPNsNeverReturnsAuthKey(t *testing.T) {
	s := apnsServer(t)
	tenant := testTenant(101)
	seedIOSIdentity(t, s, tenant, "com.example.wallet")
	key := apnsAuthKey(t)
	putAPNs(t, s, tenant, key, 0, http.StatusOK)

	c, recorder := testContext(t, tenant, "GET", "/v1/admin/push/credentials", nil)
	s.getPushCredentials(c)
	body := recorder.Body.String()
	raw, _ := base64.StdEncoding.DecodeString(key)
	if bytes.Contains([]byte(body), raw) || bytes.Contains([]byte(body), []byte(key)) {
		t.Fatal(".p8 漏进了接口响应")
	}
	if !bytes.Contains([]byte(body), []byte("ABCDE12345")) {
		t.Fatalf("Team ID 不是机密，界面要靠它回答「现在用的是哪把钥匙」：%s", body)
	}
}

// 乐观锁只认这个租户自己那一行。第二次保存必须带上新版本号。
func TestDBAPNsOptimisticLock(t *testing.T) {
	s := apnsServer(t)
	tenant := testTenant(102)
	seedIOSIdentity(t, s, tenant, "com.example.wallet")
	putAPNs(t, s, tenant, apnsAuthKey(t), 0, http.StatusOK)
	putAPNs(t, s, tenant, apnsAuthKey(t), 0, http.StatusConflict)
	putAPNs(t, s, tenant, apnsAuthKey(t), 1, http.StatusOK)
}

// 平台那一行（tenant 0）没有自己的 bundle id，所以不探活也不该被 bundle id 卡住
// ——它服务的是所有继承者，借哪个租户的 bundle id 都没有正确答案。
func TestDBAPNsPlatformRowSkipsProbe(t *testing.T) {
	s := apnsServer(t)
	tenant := testTenant(103)
	// 平台那一行是全局的，租户号换不掉它。测试库是持久的，所以前后都要清：
	// 前面清是因为上一次跑崩在中间会留下一行，表现成这一次的 409。
	clean := func() {
		s.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, pushcreds.PlatformTenant, pushcreds.APNsConfigKey)
	}
	clean()
	defer clean()
	c, recorder := testContext(t, tenant, "PUT", "/v1/admin/platform/push/credentials/apns",
		map[string]any{"authKeyP8": apnsAuthKey(t), "teamId": "ABCDE12345", "keyId": "XYZ9876543",
			"expectedVersion": 0, "reason": "平台默认 iOS 推送", "confirm": true})
	c.Set("actorId", "tester")
	s.updatePlatformPushCredentialsAPNs(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("平台行应当能在没有 bundle id 时保存：%d %s", recorder.Code, recorder.Body.String())
	}
	// 响应是平台控制台的视图：平台自己那一行，带继承它的租户数（不按请求上的租户取）
	view, _ := decodeBody(t, recorder)["apns"].(map[string]any)
	if view["inherited"] != false || view["sourceTenant"] != pushcreds.PlatformTenant || view["inheritors"] == nil {
		t.Fatalf("平台行保存后的视图：%v", view)
	}
	// 租户没有自己那一行时继承平台的
	tenantView, err := s.pushCredentialsView(context.Background(), tenant)
	if err != nil || tenantView["apns"].(gin.H)["inherited"] != true {
		t.Fatalf("租户应当显示为继承：%v %v", tenantView, err)
	}
}

// 传错文件（推送证书而不是 .p8）要在保存时就说清楚。
func TestDBAPNsRejectsCertificate(t *testing.T) {
	s := apnsServer(t)
	tenant := testTenant(104)
	seedIOSIdentity(t, s, tenant, "com.example.wallet")
	cert := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}))
	c, recorder := testContext(t, tenant, "PUT", "/v1/admin/push/credentials/apns",
		map[string]any{"authKeyP8": cert, "teamId": "ABCDE12345", "keyId": "XYZ9876543",
			"expectedVersion": 0, "reason": "配置 iOS 推送", "confirm": true})
	c.Set("actorId", "tester")
	s.updatePushCredentialsAPNs(c)
	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("状态码 %d：%s", recorder.Code, recorder.Body.String())
	}
	if body := recorder.Body.String(); !bytes.Contains([]byte(body), []byte("PUSH_CREDENTIAL_IS_CERTIFICATE")) {
		t.Fatalf("要给出专门的 code，不能只说「格式不对」：%s", body)
	}
}
