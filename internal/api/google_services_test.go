package api

import (
	"encoding/base64"
	"strings"
	"testing"
)

const androidClientJSON = `{
  "project_info": {"project_id": "anyfun-prod"},
  "client": [
    {"client_info": {"android_client_info": {"package_name": "com.anyfun.wallet"}}},
    {"client_info": {"android_client_info": {"package_name": "com.anyfun.wallet.staging"}}}
  ]
}`

func TestGoogleServicesPackagesListsEveryAndroidClient(t *testing.T) {
	got := googleServicesPackages([]byte(androidClientJSON))
	if len(got) != 2 || got[0] != "com.anyfun.wallet" || got[1] != "com.anyfun.wallet.staging" {
		t.Fatalf("packages = %v", got)
	}
}

// 一个 Firebase 项目下可以注册多个 Android 应用，所以"文件对不对"问的是
// "它的 client 里有没有我们这个包名"，不是"第一个 client 是不是我们"。
func TestGoogleServicesAcceptsAnyMatchingClient(t *testing.T) {
	if problem := googleServicesPackageProblem([]byte(androidClientJSON), "com.anyfun.wallet.staging"); problem != "" {
		t.Fatalf("a registered package was rejected: %s", problem)
	}
}

// 这是这条链路上最沉默的一种配错：包名对不上，构建成功、APK 能装，只有推送在
// 用户手机上静默失效。所以报错必须把两边的包名都说出来。
func TestGoogleServicesRejectsAnotherAppsFile(t *testing.T) {
	problem := googleServicesPackageProblem([]byte(androidClientJSON), "com.other.app")
	if problem == "" {
		t.Fatal("a file for a different package was accepted")
	}
	if !strings.Contains(problem, "com.anyfun.wallet") || !strings.Contains(problem, "com.other.app") {
		t.Fatalf("the message does not name both packages: %s", problem)
	}
}

func TestGoogleServicesRejectsAFileWithNoAndroidClient(t *testing.T) {
	if problem := googleServicesPackageProblem([]byte(`{"project_info":{"project_id":"x"},"client":[]}`), "com.anyfun.wallet"); problem == "" {
		t.Fatal("a file with no android client was accepted")
	}
	// iOS-only 的 client 也算没有 Android 应用
	iosOnly := `{"project_info":{},"client":[{"client_info":{"ios_client_info":{"bundle_id":"com.anyfun.wallet"}}}]}`
	if problem := googleServicesPackageProblem([]byte(iosOnly), "com.anyfun.wallet"); problem == "" {
		t.Fatal("an iOS-only client counted as an android registration")
	}
}

func TestStoredGoogleServicesPackagesHandlesAbsentAndBrokenValues(t *testing.T) {
	if got := storedGoogleServicesPackages(""); len(got) != 0 {
		t.Fatalf("empty config produced %v", got)
	}
	if got := storedGoogleServicesPackages("not base64!!"); len(got) != 0 {
		t.Fatalf("undecodable config produced %v", got)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(androidClientJSON))
	if got := storedGoogleServicesPackages(encoded); len(got) != 2 {
		t.Fatalf("stored config produced %v", got)
	}
}

// 服务账号凭据里有 private_key，传错了会被原样编进 APK 发给所有用户。
// 这道闸在包名检查之前，因为它的后果不可逆。
func TestServiceAccountCredentialsAreStillRejectedFirst(t *testing.T) {
	serviceAccount := []byte(`{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----","project_id":"x"}`)
	if err := rejectServiceAccountJSON(serviceAccount); err == nil {
		t.Fatal("service account credentials were accepted as google-services.json")
	}
}
