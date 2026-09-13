package pushcreds

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/secretbox"
)

const testKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func serviceAccountJSON(projectID string) []byte {
	raw, _ := json.Marshal(map[string]string{
		"type": "service_account", "project_id": projectID,
		"private_key_id": "3f9a1b2c4d5e6f708192a3b4c5d6e7f809112233",
		"private_key":    "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
		"client_email":   "firebase-adminsdk-fbsvc@" + projectID + ".iam.gserviceaccount.com",
		"token_uri":      "https://oauth2.googleapis.com/token",
	})
	return raw
}

// 挡在这里的每一条，放过去都会变成运行时一句看不懂的 OAuth 错误——而那时唯一的
// 症状是"推送发不出去"。
func TestParseServiceAccountRejectsWhatCannotSignAJWT(t *testing.T) {
	if _, err := ParseServiceAccount(serviceAccountJSON("anyfun")); err != nil {
		t.Fatalf("一份正常的服务账号被拒了：%v", err)
	}
	for name, tc := range map[string]struct{ raw, want string }{
		"不是 JSON":       {"这不是 json", "合法的 JSON"},
		"少 private_key": {`{"type":"service_account","project_id":"p","client_email":"e","private_key_id":"k"}`, "private_key"},
		"类型不对":          {`{"type":"authorized_user","project_id":"p","client_email":"e","private_key_id":"k","private_key":"-----BEGIN PRIVATE KEY-----"}`, "service_account"},
		"少 project_id":  {`{"type":"service_account","client_email":"e","private_key_id":"k","private_key":"-----BEGIN PRIVATE KEY-----"}`, "project_id"},
		"私钥不像 PEM":      {`{"type":"service_account","project_id":"p","client_email":"e","private_key_id":"k","private_key":"abc"}`, "PEM"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseServiceAccount([]byte(tc.raw))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("报错没点明原因（想看到 %q）：%v", tc.want, err)
			}
		})
	}
}

// 两份文件都来自同一个 Firebase 项目、都叫 json、都从控制台下载。拿混是迟早的事，
// 而拿混之后的表现是"存下去了，推送却不通"。build_config.go 那边已经拒绝反过来的
// 情况，这里是对称的另一半。
func TestGoogleServicesFileIsRejectedWithAPointerToTheRightPlace(t *testing.T) {
	googleServices := `{"project_info":{"project_number":"393818650719","project_id":"anyfun"},
		"client":[{"client_info":{"android_client_info":{"package_name":"com.anyfun.foundation"}}}]}`
	_, err := ParseServiceAccount([]byte(googleServices))
	if !errors.Is(err, ErrLooksLikeGoogleServices) {
		t.Fatalf("google-services.json 必须被识别出来：%v", err)
	}
	if !strings.Contains(err.Error(), "服务账号") {
		t.Fatalf("报错要说清楚去哪儿拿对的那一份：%v", err)
	}
}

// 密文绑在**生效行**的租户上：一个租户的密文搬到另一个租户名下必须解不开。
// 平台行继承给租户时，解密用的也必须是平台那一行的 id，否则继承整条链断掉。
func TestCiphertextIsBoundToTheRowItWasSavedUnder(t *testing.T) {
	box, err := secretbox.New(testKey)
	if err != nil {
		t.Fatal(err)
	}
	raw := serviceAccountJSON("anyfun")
	sealed, err := Encrypt(box, PlatformTenant, raw)
	if err != nil {
		t.Fatal(err)
	}

	// 生效行是平台的 0：解得开
	platform := Record{Value: FCM{ServiceAccountEncrypted: sealed}, SourceTenant: PlatformTenant}
	account, err := platform.ServiceAccount(box)
	if err != nil {
		t.Fatalf("平台行自己解不开：%v", err)
	}
	if account.ProjectID != "anyfun" {
		t.Fatalf("解出来的项目不对：%q", account.ProjectID)
	}

	// 同一段密文挂在别的租户名下：解不开
	moved := Record{Value: FCM{ServiceAccountEncrypted: sealed}, SourceTenant: "100000001"}
	if _, err := moved.ServiceAccount(box); err == nil {
		t.Fatal("密文被搬到另一个租户名下之后必须解不开")
	}
}

func TestInheritedIsAboutTheRowNotTheRequest(t *testing.T) {
	platform := Record{SourceTenant: PlatformTenant}
	if !platform.Inherited("100000001") {
		t.Fatal("平台行对租户来说是继承来的")
	}
	own := Record{SourceTenant: "100000001"}
	if own.Inherited("100000001") {
		t.Fatal("自己的行不是继承")
	}
}

func TestKeyHintNeverPrintsTheWholeID(t *testing.T) {
	full := "3f9a1b2c4d5e6f708192a3b4c5d6e7f809112233"
	hint := KeyHint(full)
	if hint == full || !strings.HasPrefix(full, strings.TrimSuffix(hint, "…")) {
		t.Fatalf("密钥 id 提示不对：%q", hint)
	}
}
