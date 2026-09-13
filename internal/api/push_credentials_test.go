package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/config"
	"github.com/Helix2010/RN-Server/internal/pushcreds"
	"github.com/Helix2010/RN-Server/internal/secretbox"
	"github.com/gin-gonic/gin"
)

// pushServer 造一个能保存推送凭据的服务端：主密钥齐了，联网验证换成本地桩。
//
// 验证之所以必须能替换：保存这条路**真的**会去 Google 换一次令牌（那正是这个
// 设计的重点，CredentialsFromJSON 不联网、证明不了钥匙还有效），而测试不该联网。
func pushServer(t *testing.T) *server {
	t.Helper()
	box, err := secretbox.New(base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return &server{
		db: openTestDB(t), secrets: box, cfg: config.Config{Environment: "test", MySQLQueryTimeout: 10},
		verifyFCM: func(context.Context, pushcreds.ServiceAccount) error { return nil },
	}
}

func fcmServiceAccount(projectID string) string {
	raw, _ := json.Marshal(map[string]string{
		"type": "service_account", "project_id": projectID,
		"private_key_id": "3f9a1b2c4d5e6f708192a3b4c5d6e7f809112233",
		"private_key":    "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
		"client_email":   "firebase-adminsdk-fbsvc@" + projectID + ".iam.gserviceaccount.com",
		"token_uri":      "https://oauth2.googleapis.com/token",
	})
	return base64.StdEncoding.EncodeToString(raw)
}

func googleServicesFor(projectID, packageName string) string {
	raw, _ := json.Marshal(map[string]any{
		"project_info": map[string]string{"project_number": "393818650719", "project_id": projectID},
		"client": []map[string]any{{
			"client_info": map[string]any{
				"mobilesdk_app_id":    "1:393818650719:android:abc",
				"android_client_info": map[string]string{"package_name": packageName},
			},
		}},
	})
	return base64.StdEncoding.EncodeToString(raw)
}

// seedGoogleServices 直接写 build.android，绕开那一页的其它必填项。
func seedGoogleServices(t *testing.T, s *server, tenant, projectID, packageName string) {
	t.Helper()
	value, _ := json.Marshal(buildConfig{
		RepoDirectory:      "seeded",
		GoogleServicesJSON: googleServicesFor(projectID, packageName),
		Identity:           appIdentity{AppName: "Seeded", Scheme: "seeded"},
	})
	if _, err := s.db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
		VALUES(?,?,?,1,'test',UTC_TIMESTAMP(3)) ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)`,
		tenant, buildConfigKey, value); err != nil {
		t.Fatal(err)
	}
}

func putFCM(t *testing.T, s *server, tenant, serviceAccount string, expectedVersion, want int) map[string]any {
	t.Helper()
	c, recorder := testContext(t, tenant, "PUT", "/v1/admin/push/credentials/fcm",
		map[string]any{"serviceAccountJson": serviceAccount, "expectedVersion": expectedVersion,
			"reason": "配置推送凭据", "confirm": true})
	c.Set("actorId", "tester")
	s.updatePushCredentialsFCM(c)
	if recorder.Code != want {
		t.Fatalf("状态码 %d，期望 %d：%s", recorder.Code, want, recorder.Body.String())
	}
	return decodeBody(t, recorder)
}

// 这一条钉住的是整个设计的理由：服务账号（留服务端）和 google-services.json
// （编进 APK）必须属于同一个 Firebase 项目。对不上时构建成功、安装成功、token
// 注册成功，只有推送发不出去——没有任何一步会报错。
func TestDBPushCredentialProjectMustMatchGoogleServices(t *testing.T) {
	s := pushServer(t)
	tenant := testTenant(60)
	seedGoogleServices(t, s, tenant, "anyfun", "com.anyfun.foundation")

	// 另一个项目的服务账号：拒绝，两个 id 都要出现在报错里
	body := putFCM(t, s, tenant, fcmServiceAccount("someone-else"), 0, http.StatusUnprocessableEntity)
	if body["code"] != "FCM_PROJECT_MISMATCH" {
		t.Fatalf("code = %v", body["code"])
	}
	detail, _ := body["detail"].(string)
	if !strings.Contains(detail, "someone-else") || !strings.Contains(detail, "anyfun") {
		t.Fatalf("报错要同时点出两个项目：%q", detail)
	}

	// 同一个项目：存得下去
	putFCM(t, s, tenant, fcmServiceAccount("anyfun"), 0, http.StatusOK)
}

// 反方向：先配了凭据，后换一份别的项目的 google-services.json。这是这条链路上
// 最容易发生的顺序，漏掉它等于只做了一半校验。
func TestDBGoogleServicesMustMatchTheStoredPushCredential(t *testing.T) {
	s := pushServer(t)
	tenant := testTenant(61)
	seedGoogleServices(t, s, tenant, "anyfun", "com.anyfun.foundation")
	putFCM(t, s, tenant, fcmServiceAccount("anyfun"), 0, http.StatusOK)

	if detail := s.pushCredentialProjectProblem(context.Background(), tenant, "anyfun"); detail != "" {
		t.Fatalf("同项目不该报错：%q", detail)
	}
	detail := s.pushCredentialProjectProblem(context.Background(), tenant, "another-project")
	if !strings.Contains(detail, "another-project") || !strings.Contains(detail, "anyfun") {
		t.Fatalf("报错要同时点出两个项目：%q", detail)
	}
}

// 继承来的凭据同样要比，而且报错必须说清楚"那是平台默认的"——否则看的人会
// 在自己的页面上找一份根本不在那儿的配置。
func TestDBInheritedCredentialMismatchSaysWhereItComesFrom(t *testing.T) {
	s := pushServer(t)
	tenant := testTenant(62)
	// 平台默认：项目 anyfun
	putFCM(t, s, pushcreds.PlatformTenant, fcmServiceAccount("anyfun"), 0, http.StatusOK)
	defer s.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, pushcreds.PlatformTenant, pushcreds.FCMConfigKey)

	detail := s.pushCredentialProjectProblem(context.Background(), tenant, "tenant-own-project")
	if !strings.Contains(detail, "平台默认") {
		t.Fatalf("继承来的不匹配必须点明来源：%q", detail)
	}
	if !strings.Contains(detail, "单独配") {
		t.Fatalf("报错要给出两条出路之一：给本租户单独配一份：%q", detail)
	}
}

// 平台那一行是所有没单独配的租户共用的。视图上必须看得出"这是继承来的"，
// 否则运营会以为自己配过。
func TestDBTenantInheritsThePlatformCredential(t *testing.T) {
	s := pushServer(t)
	tenant := testTenant(63)
	putFCM(t, s, pushcreds.PlatformTenant, fcmServiceAccount("anyfun"), 0, http.StatusOK)
	defer s.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, pushcreds.PlatformTenant, pushcreds.FCMConfigKey)

	view, err := s.pushCredentialsView(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	fcm, _ := view["fcm"].(gin.H)
	if fcm["configured"] != true || fcm["inherited"] != true {
		t.Fatalf("租户应当继承平台那一行：%#v", fcm)
	}
	if fcm["projectId"] != "anyfun" {
		t.Fatalf("继承来的项目不对：%v", fcm["projectId"])
	}
	// 还没传 google-services.json：匹配与否无从谈起，必须是 null 而不是一个红叉
	if fcm["projectMatches"] != nil {
		t.Fatalf("只配了一半时 projectMatches 必须是 null，得到 %v", fcm["projectMatches"])
	}

	seedGoogleServices(t, s, tenant, "anyfun", "com.anyfun.foundation")
	view, _ = s.pushCredentialsView(context.Background(), tenant)
	fcm, _ = view["fcm"].(gin.H)
	if fcm["projectMatches"] != true {
		t.Fatalf("两边同项目时应当为 true：%#v", fcm)
	}
}

// 私钥不经任何接口回去。这一条一旦破了，一个只读的管理员就能把发推送的能力
// 整个拿走。
func TestDBPushCredentialViewNeverReturnsThePrivateKey(t *testing.T) {
	s := pushServer(t)
	tenant := testTenant(64)
	seedGoogleServices(t, s, tenant, "anyfun", "com.anyfun.foundation")
	putFCM(t, s, tenant, fcmServiceAccount("anyfun"), 0, http.StatusOK)

	view, err := s.pushCredentialsView(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	serialized, _ := json.Marshal(view)
	for _, forbidden := range []string{"PRIVATE KEY", "private_key", "serviceAccountEncrypted", "MIIB"} {
		if bytes.Contains(serialized, []byte(forbidden)) {
			t.Fatalf("视图里出现了 %q：%s", forbidden, serialized)
		}
	}
	// key id 只给前 8 位
	fcm, _ := view["fcm"].(gin.H)
	if hint, _ := fcm["privateKeyIdHint"].(string); !strings.HasPrefix(hint, "3f9a1b2c") || len(hint) > 12 {
		t.Fatalf("密钥 id 提示不对：%q", hint)
	}
}

// 传错文件是迟早的事：两份都来自同一个 Firebase 项目、都叫 json、都从控制台下载。
func TestDBUploadingGoogleServicesAsCredentialIsRejectedWithDirections(t *testing.T) {
	s := pushServer(t)
	body := putFCM(t, s, testTenant(65), googleServicesFor("anyfun", "com.anyfun.foundation"), 0, http.StatusUnprocessableEntity)
	if body["code"] != "PUSH_CREDENTIAL_IS_GOOGLE_SERVICES" {
		t.Fatalf("code = %v", body["code"])
	}
	if detail, _ := body["detail"].(string); !strings.Contains(detail, "服务账号") {
		t.Fatalf("报错要告诉人去哪儿拿对的那一份：%q", detail)
	}
}

// Google 拒绝这把钥匙时不能保存。保存一把换不到令牌的钥匙，等于把"推送为什么
// 不通"这个问题从 env 挪进库里。
func TestDBCredentialRejectedByGoogleIsNotSaved(t *testing.T) {
	s := pushServer(t)
	s.verifyFCM = func(context.Context, pushcreds.ServiceAccount) error { return pushcreds.ErrTokenExchangeFailed }
	tenant := testTenant(66)
	putFCM(t, s, tenant, fcmServiceAccount("anyfun"), 0, http.StatusFailedDependency)

	view, err := s.pushCredentialsView(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	fcm, _ := view["fcm"].(gin.H)
	if fcm["configured"] != false {
		t.Fatalf("被 Google 拒绝的钥匙不该留在库里：%#v", fcm)
	}
}

// 删平台那一行不是"删一个配置"，是"关掉所有没单独配的租户的推送"。
func TestDBDeletingThePlatformRowRequiresKnowingWhoInheritsIt(t *testing.T) {
	s := pushServer(t)
	putFCM(t, s, pushcreds.PlatformTenant, fcmServiceAccount("anyfun"), 0, http.StatusOK)
	defer s.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, pushcreds.PlatformTenant, pushcreds.FCMConfigKey)

	if s.pushCredentialInheritors(context.Background()) == 0 {
		t.Skip("这个库里没有启用中的租户，数不出继承者")
	}
	c, recorder := testContext(t, pushcreds.PlatformTenant, "DELETE", "/v1/admin/platform/push/credentials/fcm?reason=轮换", nil)
	c.Set("actorId", "tester")
	s.deletePlatformPushCredentialsFCM(c)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("有继承者时不带 confirm 必须被挡住，得到 %d：%s", recorder.Code, recorder.Body.String())
	}
	body := decodeBody(t, recorder)
	if body["code"] != "PUSH_CREDENTIAL_INHERITED" {
		t.Fatalf("code = %v", body["code"])
	}
	if detail, _ := body["detail"].(string); !strings.Contains(detail, "推送会立刻停") {
		t.Fatalf("确认提示要说清后果：%q", detail)
	}
}

// 乐观锁认的是**这个租户自己**那一行：继承来的版本号不是它的，拿它当
// expectedVersion 会让第一次保存莫名其妙地 409。
func TestDBExpectedVersionIgnoresTheInheritedRow(t *testing.T) {
	s := pushServer(t)
	tenant := testTenant(67)
	putFCM(t, s, pushcreds.PlatformTenant, fcmServiceAccount("anyfun"), 0, http.StatusOK)
	defer s.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`, pushcreds.PlatformTenant, pushcreds.FCMConfigKey)

	// 平台那一行版本是 1，但租户自己还没有行，所以第一次保存要用 0
	putFCM(t, s, tenant, fcmServiceAccount("anyfun"), 0, http.StatusOK)
	// 第二次才是 1
	putFCM(t, s, tenant, fcmServiceAccount("anyfun"), 1, http.StatusOK)
	putFCM(t, s, tenant, fcmServiceAccount("anyfun"), 1, http.StatusConflict)
}
