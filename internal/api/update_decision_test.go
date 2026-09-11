package api

import (
	"strings"
	"testing"
)

func TestResolveUpdateDecisionWithoutAnyRequirement(t *testing.T) {
	decision := resolveUpdateDecision(updateDecisionInput{
		Current: "1.2.4", Minimum: "1.0.0", Latest: "1.2.4",
		Distribution: "direct", ActionURL: "https://api.example/download",
	})
	if decision != "none" {
		t.Fatalf("decision = %q", decision)
	}
}

func TestResolveUpdateDecisionRecommendsANewerVersion(t *testing.T) {
	decision := resolveUpdateDecision(updateDecisionInput{
		Current: "1.2.0", Minimum: "1.0.0", Latest: "1.2.4",
		Distribution: "direct", ActionURL: "https://api.example/download",
	})
	if decision != "recommended" {
		t.Fatalf("decision = %q", decision)
	}
}

func TestResolveUpdateDecisionRequiresBelowTheMinimum(t *testing.T) {
	decision := resolveUpdateDecision(updateDecisionInput{
		Current: "0.9.0", Minimum: "1.0.0", Latest: "1.2.4",
		Distribution: "direct", ActionURL: "https://api.example/download",
	})
	if decision != "required" {
		t.Fatalf("decision = %q", decision)
	}
}

func TestResolveUpdateDecisionHonoursAMandatoryRelease(t *testing.T) {
	// 运营在发布时勾了强制升级：不必再手改全局最低版本
	decision := resolveUpdateDecision(updateDecisionInput{
		Current: "1.2.0", Minimum: "1.0.0", Latest: "1.2.4",
		Distribution: "direct", ActionURL: "https://api.example/download",
		MandatoryVersion: "1.2.4",
	})
	if decision != "required" {
		t.Fatalf("decision = %q", decision)
	}
}

func TestResolveUpdateDecisionNeverLowersTheBar(t *testing.T) {
	// 把老版本标成强制再激活，不该让所有人被要求"升级"到更老的包
	decision := resolveUpdateDecision(updateDecisionInput{
		Current: "1.2.0", Minimum: "1.2.0", Latest: "1.2.4",
		Distribution: "direct", ActionURL: "https://api.example/download",
		MandatoryVersion: "1.1.0",
	})
	if decision != "recommended" {
		t.Fatalf("decision = %q，强制标记不能把最低版本拉低", decision)
	}
}

func TestResolveUpdateDecisionKeepsRequiredWhenAChannelHasNoDownloadYet(t *testing.T) {
	// 以前这里会静默降级成 recommended，运营以为强更生效了、用户却看到
	// 带"稍后再说"的软更。正式渠道必须保持 required，App 侧有"暂时拿不到
	// 安装包"的兜底提示和重试。
	decision := resolveUpdateDecision(updateDecisionInput{
		Current: "0.9.0", Minimum: "1.2.4", Latest: "1.2.4",
		Distribution: "store", ActionURL: "",
	})
	if decision != "required" {
		t.Fatalf("decision = %q", decision)
	}
}

func TestResolveUpdateDecisionDoesNotLockDevelopmentBuilds(t *testing.T) {
	// development 渠道本来就没有安装入口，锁死只会把自己人挡在外面
	decision := resolveUpdateDecision(updateDecisionInput{
		Current: "0.9.0", Minimum: "1.2.4", Latest: "1.2.4",
		Distribution: "development", ActionURL: "",
	})
	if decision != "recommended" {
		t.Fatalf("decision = %q", decision)
	}
}

// 换签名密钥之后，老密钥签的装机装不上新包（Android 不允许签名不同的 APK 覆盖安装）。
// 应用内直装必须在这种组合下关掉，否则用户只会看到一个点一次失败一次的按钮；
// 强制升级时那是个死循环（安全评审 N1 的迁移窗口，runbook §8.5）。
func TestDirectInstallAllowedAcrossASignerRotation(t *testing.T) {
	const oldSigner = "fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c"
	const newSigner = "1a5d9fb446e2f4c8e1aa464a02b14248a265ea9c554f83eb01ec94886329e694"

	for name, tc := range map[string]struct {
		enabled   bool
		platform  string
		installed string
		target    string
		want      bool
	}{
		"同一把密钥：照常直装":     {true, "android", newSigner, newSigner, true},
		"大小写不同也算同一把":     {true, "android", strings.ToUpper(newSigner), newSigner, true},
		"轮换过密钥：关掉直装":     {true, "android", oldSigner, newSigner, false},
		"不知道装的是哪个 build": {true, "android", "", newSigner, true},
		"目标包没记指纹（旧记录）":   {true, "android", oldSigner, "", true},
		"两边都不知道":         {true, "android", "", "", true},
		"租户本来就关了直装":      {false, "android", newSigner, newSigner, false},
		"iOS 没有直装这回事":    {true, "ios", newSigner, newSigner, false},
		"轮换过但租户也关了":      {false, "android", oldSigner, newSigner, false},
	} {
		if got := directInstallAllowed(tc.enabled, tc.platform, tc.installed, tc.target); got != tc.want {
			t.Fatalf("%s: directInstallAllowed = %v, want %v", name, got, tc.want)
		}
	}
}
