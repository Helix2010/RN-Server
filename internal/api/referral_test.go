package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// 邀请配置只有两个旋钮，越界值必须在**写入时**拒绝：读路径不修复坏数据，
// 而且新版 App 的 bootstrap schema 会校验取值，下发越界值会让新版 App 整份
// safeParse 失败（设计 §3.6）。
func TestValidateReferralSection(t *testing.T) {
	cases := []struct {
		name    string
		section any
		wantErr bool
	}{
		{name: "空对象合法", section: map[string]any{}},
		{name: "两个旋钮都给", section: map[string]any{"enabled": true, "bindWindowHours": float64(168)}},
		{name: "只给开关", section: map[string]any{"enabled": false}},
		{name: "窗口下界", section: map[string]any{"bindWindowHours": float64(referralMinBindWindowHours)}},
		{name: "窗口上界", section: map[string]any{"bindWindowHours": float64(referralMaxBindWindowHours)}},
		{name: "不是对象", section: []any{}, wantErr: true},
		{name: "未知键", section: map[string]any{"maxDepth": float64(5)}, wantErr: true},
		{name: "enabled 不是布尔", section: map[string]any{"enabled": "yes"}, wantErr: true},
		{name: "窗口不是数字", section: map[string]any{"bindWindowHours": "168"}, wantErr: true},
		{name: "窗口不是整数", section: map[string]any{"bindWindowHours": 1.5}, wantErr: true},
		{name: "窗口为零", section: map[string]any{"bindWindowHours": float64(0)}, wantErr: true},
		{name: "窗口为负", section: map[string]any{"bindWindowHours": float64(-1)}, wantErr: true},
		{name: "窗口超上界", section: map[string]any{"bindWindowHours": float64(referralMaxBindWindowHours + 1)}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateReferralSection(tc.section)
			if tc.wantErr && err == nil {
				t.Fatalf("expected the write to be rejected")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
		})
	}
}

// 报错必须说清是哪个键、填了什么、期望什么（AGENTS.md：二十几个键共用一句报错等于没有报错）。
func TestValidateReferralSectionErrorsNameTheKey(t *testing.T) {
	err := validateReferralSection(map[string]any{"bindWindowHours": float64(99999)})
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"bindWindowHours", "99999"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err.Error(), want)
		}
	}
}

// 未配置时用声明式默认，且默认是"关"——它会在 App 上多出一个入口，该由运营明确打开。
func TestNormalizeReferralDefaults(t *testing.T) {
	out := normalizeReferral(nil)
	if out["enabled"] != false {
		t.Fatalf("referral must default to disabled, got %v", out["enabled"])
	}
	if out["bindWindowHours"] != referralDefaultBindWindowHours {
		t.Fatalf("bindWindowHours = %v, want %d", out["bindWindowHours"], referralDefaultBindWindowHours)
	}
}

func TestNormalizeReferralKeepsConfiguredValues(t *testing.T) {
	out := normalizeReferral(map[string]any{"enabled": true, "bindWindowHours": float64(24)})
	if out["enabled"] != true || out["bindWindowHours"] != 24 {
		t.Fatalf("configured values were not carried through: %v", out)
	}
}

// 下发链路才带 inviteLinkBase，它由服务端按请求 Host 算（设计 §3.6）。
func TestReferralBootstrapSectionCarriesLinkBase(t *testing.T) {
	out := referralBootstrapSection(map[string]any{"enabled": true}, "https://api.example.com/app/invite/")
	if out["inviteLinkBase"] != "https://api.example.com/app/invite/" {
		t.Fatalf("inviteLinkBase must come from the server, got %v", out["inviteLinkBase"])
	}
	if out["enabled"] != true {
		t.Fatalf("configured values were not carried through: %v", out)
	}
}

// bootstrap 复用 appConfigView 归一化过的 config，referral 段因此会被归一化两遍。
// 第二遍必须仍读得出租户配的窗口：只认 float64 的话，第一遍产出的 int 会断言失败、
// 静默退回默认 168 小时，而 bindReferral 读的是库里的原始 JSON，判的还是 24。
// 那正好是最难查的一类故障——App 显示"还能绑"，服务端返回 REFERRAL_WINDOW_CLOSED。
func TestReferralSectionSurvivesDoubleNormalize(t *testing.T) {
	stored := map[string]any{"enabled": true, "bindWindowHours": float64(24)}
	view := normalizeReferral(stored)
	again := referralBootstrapSection(view, "https://api.example.com/app/invite/")
	if again["bindWindowHours"] != 24 {
		t.Fatalf("second normalize lost the configured window: %v", again["bindWindowHours"])
	}
	if again["enabled"] != true {
		t.Fatalf("second normalize lost the enabled flag: %v", again["enabled"])
	}
}

// 配置中心是"整份配置 PATCH 回去"：管理端回显里出现的键会原样发回来。
// 所以管理端视图给出的 referral 段必须能通过写入校验，否则管理员改任何一项
// 配置（主题色、文案、更新策略）都会被 INVALID_REFERRAL_CONFIG 拒掉。
// 走一遍 JSON 是为了忠实还原线上形态：int 过网线回来是 float64。
func TestAdminReferralViewSavesBackUnchanged(t *testing.T) {
	for _, stored := range []map[string]any{
		nil,
		{"enabled": true, "bindWindowHours": float64(24)},
	} {
		wire, err := json.Marshal(normalizeReferral(stored))
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var back any
		if err := json.Unmarshal(wire, &back); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if err := validateReferralSection(back); err != nil {
			t.Fatalf("管理端回显的 referral 段存不回去（%s）：%v", wire, err)
		}
	}
}

// 邀请链接的路径必须带尾斜杠：Android 的 pathPrefix 是前缀匹配，
// 不带斜杠会把 /app/invitexyz 也吃进来（设计 §5.4）。
func TestReferralInvitePathHasTrailingSlash(t *testing.T) {
	if referralInvitePath != "/app/invite/" {
		t.Fatalf("referralInvitePath = %q, want /app/invite/", referralInvitePath)
	}
}

// 别名必须随观察者变化，否则两个邀请人能拿各自看到的别名互相 join。
func TestReferralAliasIsPerViewer(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	a := referralAlias(key, 1, 42)
	b := referralAlias(key, 2, 42)
	if a == b {
		t.Fatalf("two viewers see the same alias %q for the same invitee", a)
	}
	if a != referralAlias(key, 1, 42) {
		t.Fatal("alias must be stable for the same viewer and invitee")
	}
	if len(a) != referralAliasLength {
		t.Fatalf("alias length = %d, want %d", len(a), referralAliasLength)
	}
}

// 换一把密钥就换一套别名：别名不能只靠 id 推出来。
func TestReferralAliasDependsOnKey(t *testing.T) {
	first := referralAlias([]byte("key-one"), 1, 2)
	second := referralAlias([]byte("key-two"), 1, 2)
	if first == second {
		t.Fatal("alias must depend on the secret, otherwise it is just a hash of the ids")
	}
}

// 上溯是有界的：链路超过上界要能报出来，而不是一直查下去。
func TestReferralMaxDepthIsSmall(t *testing.T) {
	// 绑定在 GET_LOCK 里串行执行，链路越长持锁越久。个位数是设计 D6 的明确要求。
	if referralMaxDepth < 1 || referralMaxDepth > 9 {
		t.Fatalf("referralMaxDepth = %d, design requires a single-digit bound", referralMaxDepth)
	}
}
