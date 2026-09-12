package api

import (
	"strings"
	"testing"
)

func validIdentity() appIdentity {
	return appIdentity{
		AppName:    "AnyFun",
		Scheme:     "anyfun",
		APIBaseURL: "https://api.anyfun.win",
	}
}

func TestAppIdentityRejectsWhatWouldProduceABrokenApp(t *testing.T) {
	for name, mutate := range map[string]func(*appIdentity){
		"应用名为空": func(a *appIdentity) { a.AppName = "  " },
		// scheme 决定这个 App 认领哪些深链，写松了就是去抢别人的链接
		"scheme 带大写":   func(a *appIdentity) { a.Scheme = "AnyFun" },
		"scheme 以数字开头": func(a *appIdentity) { a.Scheme = "1fun" },
		// 配置地址允许 http 等于把整份配置放在明文链路上；签名挡不住"根本没连到我们"
		"配置地址是 http": func(a *appIdentity) { a.APIBaseURL = "http://api.anyfun.win" },
		"配置地址带路径":    func(a *appIdentity) { a.APIBaseURL = "https://api.anyfun.win/v1" },
		"配置地址为空":     func(a *appIdentity) { a.APIBaseURL = "" },
		"底色不是十六进制":   func(a *appIdentity) { a.IconBackgroundColor = "white" },
	} {
		identity := validIdentity()
		mutate(&identity)
		if err := identity.validate(); err == nil {
			t.Fatalf("%s 被接受了", name)
		}
	}
	if err := validIdentity().validate(); err != nil {
		t.Fatalf("合法的身份被拒了: %v", err)
	}
	// 末尾斜杠是人手填时最常见的写法，不该因此判错
	trailing := validIdentity()
	trailing.APIBaseURL = "https://api.anyfun.win/"
	if err := trailing.validate(); err != nil {
		t.Fatalf("带末尾斜杠的地址被拒了: %v", err)
	}
}

// 只有真正会让已装设备升不上去的字段才算"破坏性变更"。把改显示名也算进去，
// 运维每次改个文案都要在弹窗里确认一遍，确认框很快就会被无脑点掉。
func TestIdentityBreakingChangesOnlyCountsWhatBreaksUpgrades(t *testing.T) {
	before := validIdentity()
	renamed := before
	renamed.AppName = "AnyFun 钱包"
	if got := identityBreakingChanges(before, renamed); len(got) != 0 {
		t.Fatalf("改显示名被当成了破坏性变更: %v", got)
	}
	// 深链 scheme 改了，已经发出去的链接会打不开
	rescheme := before
	rescheme.Scheme = "other"
	if got := identityBreakingChanges(before, rescheme); len(got) != 1 || got[0] != "scheme" {
		t.Fatalf("改 scheme 没有被拦下: %v", got)
	}
	// 包名不在这里判：它归发布身份管，真正的闸是排队时和正在分发的那一版比对
	// 第一次配置（旧值为空）不算变更，否则新租户建档就要先确认一次
	fresh := identityBreakingChanges(appIdentity{}, before)
	if len(fresh) != 0 {
		t.Fatalf("首次配置被当成了变更: %v", fresh)
	}
}

// 漂移比的是"要打的包"和"正在分发的包"。这两者身份不同意味着老用户升不上去，
// 只能卸载重装——direct 分发下没有商店替我们处理这件事。
func TestTenantIdentityDriftComparesAgainstWhatUsersAlreadyHave(t *testing.T) {
	manifest := tenantManifest{
		AndroidPackage: "com.anyfun.foundation",
		SignerSHA256:   "1a5d9fb446e2f4c8e1aa464a02b14248a265ea9c554f83eb01ec94886329e694",
	}
	if drift := tenantIdentityDrift(manifest, manifest.AndroidPackage, manifest.SignerSHA256); len(drift) != 0 {
		t.Fatalf("一致时报出了漂移: %v", drift)
	}
	// 新租户还没有 active 版本，没有可比的对象，不该拦住第一个包
	if drift := tenantIdentityDrift(manifest, "", ""); len(drift) != 0 {
		t.Fatalf("新租户的第一个包被拦了: %v", drift)
	}
	drift := tenantIdentityDrift(manifest, "com.other.app", "0000000000000000000000000000000000000000000000000000000000000000")
	if len(drift) != 2 {
		t.Fatalf("包名和指纹都变了却只报了 %v", drift)
	}
	if !strings.Contains(strings.Join(drift, " "), "com.other.app") {
		t.Fatalf("漂移信息里没说清是从哪个包名变过来的: %v", drift)
	}
	// 指纹大小写不该被当成变更：入库时的归一化不保证每条历史记录都是小写
	upper := tenantIdentityDrift(manifest, manifest.AndroidPackage, strings.ToUpper(manifest.SignerSHA256))
	if len(upper) != 0 {
		t.Fatalf("只是大小写不同却报了漂移: %v", upper)
	}
}

// 两个文件都从 Firebase 控制台下载、都叫 json、名字还长得像，但性质相反：
// google-services.json 本来就会原样编进每一个 APK；service-account.json 里有
// private_key。传错的后果是那把私钥被编进 APK 发给所有用户，装出去之后只能吊销
// 密钥重发。这条用例守的就是这个。
func TestGoogleServicesUploadRefusesAServiceAccount(t *testing.T) {
	serviceAccount := []byte(`{"type":"service_account","project_id":"anyfun","private_key_id":"abc","private_key":"-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n","client_email":"a@b.iam.gserviceaccount.com"}`)
	err := rejectServiceAccountJSON(serviceAccount)
	if err == nil {
		t.Fatal("服务账号凭据被当成 google-services.json 接受了")
	}
	if !strings.Contains(err.Error(), "private_key") {
		t.Fatalf("报错没点明是 private_key: %v", err)
	}

	// 去掉 private_key 但仍标着 service_account 的，也不是正品
	if rejectServiceAccountJSON([]byte(`{"type":"service_account","project_id":"anyfun"}`)) == nil {
		t.Fatal("type=service_account 被接受了")
	}

	// 选错成别的 json（比如 firebase.json、package.json）同样要早点说
	if rejectServiceAccountJSON([]byte(`{"hosting":{}}`)) == nil {
		t.Fatal("一个不相干的 json 被接受了")
	}

	// 正品：顶层是 project_info + client
	valid := []byte(`{"project_info":{"project_id":"anyfun"},"client":[{"client_info":{"mobilesdk_app_id":"1:2:android:3"}}]}`)
	if err := rejectServiceAccountJSON(valid); err != nil {
		t.Fatalf("正常的 google-services.json 被拒了: %v", err)
	}
}
