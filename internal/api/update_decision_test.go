package api

import "testing"

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
