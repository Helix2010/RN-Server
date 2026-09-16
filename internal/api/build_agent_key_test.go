package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/Helix2010/RN-Server/internal/buildkeystore"
)

func agentKeyServer(t *testing.T) *server {
	t.Helper()
	db := openTestDB(t)
	if _, err := db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`,
		platformTenantID, buildAgentKeyConfigKey); err != nil {
		t.Fatalf("清掉上一轮的登记: %v", err)
	}
	return &server{db: db}
}

func register(t *testing.T, s *server, publicKey, agent string) map[string]any {
	t.Helper()
	c, recorder := testContext(t, platformTenantID, "POST", "/v1/build-agent/public-key", map[string]any{
		"publicKey": publicKey, "agent": agent,
	})
	s.registerBuildAgentKey(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("登记失败: %d %s", recorder.Code, recorder.Body.String())
	}
	return decodeBody(t, recorder)
}

// 第一把公钥直接定下来：这台机器此刻还没有任何密钥加密给它，没什么可保护的。
// 之后再报一把**不同**的，绝不能自动生效——持有代理令牌的人本来就能领走盒子，
// 但开不开得了要看私钥；如果换公钥不需要人确认，偷到令牌的人登记自己的公钥就够了，
// 此后每一把新密钥都直接加密给他，而现场看不出任何异常。
func TestDBBuildAgentKeyIsPinnedAfterTheFirstRegistration(t *testing.T) {
	s := agentKeyServer(t)
	_, first, _ := buildkeystore.NewAgentKey()
	_, second, _ := buildkeystore.NewAgentKey()

	if out := register(t, s, first.PublicKey, "builder-1"); out["status"] != "registered" {
		t.Fatalf("第一把应当直接登记：%v", out)
	}
	// 同一把重报是常态（代理每次启动都报一次），不该被当成换钥匙
	if out := register(t, s, first.PublicKey, "builder-1"); out["status"] != "unchanged" {
		t.Fatalf("重报同一把不该有动静：%v", out)
	}
	if out := register(t, s, second.PublicKey, "builder-2"); out["status"] != "pending_acceptance" {
		t.Fatalf("换公钥必须挂起等人确认：%v", out)
	}
	record, err := s.buildAgentKey(context.Background())
	if err != nil || record == nil {
		t.Fatal(err)
	}
	if record.Current.PublicKey != first.PublicKey {
		t.Fatal("没人确认，正在用的公钥却被换掉了")
	}
	if record.Pending == nil || record.Pending.PublicKey != second.PublicKey {
		t.Fatalf("新公钥没有被记成待确认：%+v", record.Pending)
	}
}

// 接受要抄一遍指纹：这是"你确实去那台机器上核对过"的唯一证据
func TestDBAcceptingAnAgentKeyNeedsTheMatchingFingerprint(t *testing.T) {
	s := agentKeyServer(t)
	_, first, _ := buildkeystore.NewAgentKey()
	_, second, _ := buildkeystore.NewAgentKey()
	register(t, s, first.PublicKey, "builder-1")
	register(t, s, second.PublicKey, "builder-2")

	accept := func(fingerprint string) (int, map[string]any) {
		c, recorder := testContext(t, platformTenantID, "POST", "/v1/admin/platform/build-agent/public-key/accept", map[string]any{
			"fingerprint": fingerprint, "reason": "换了打包机", "confirm": true,
		})
		c.Set("actorId", "tester")
		s.acceptBuildAgentKey(c)
		return recorder.Code, decodeBody(t, recorder)
	}

	if code, out := accept("0000000000000000"); code != http.StatusConflict || out["code"] != "AGENT_KEY_FINGERPRINT_MISMATCH" {
		t.Fatalf("指纹对不上却接受了：%d %v", code, out)
	}
	if code, out := accept(second.Fingerprint()); code != http.StatusOK || out["accepted"] != true {
		t.Fatalf("指纹对上了却没接受：%d %v", code, out)
	}
	record, _ := s.buildAgentKey(context.Background())
	if record.Current.PublicKey != second.PublicKey || record.Pending != nil {
		t.Fatalf("接受之后状态不对：%+v", record)
	}
}

// 换公钥之后，**已有的盒子还是加密给旧公钥的**——服务端没有明文，换不了。所以每个
// 租户的验证结果必须作废，让代理用新私钥重验一遍，打不开的立刻显示出来。
func TestDBAcceptingAnAgentKeyInvalidatesEveryVerification(t *testing.T) {
	s := agentKeyServer(t)
	tenant := testTenant(20)
	if _, err := s.db.Exec(`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at) VALUES(?,?,?,1,'tester',NOW())`,
		tenant, buildKeystoreCheckConfigKey, `{"version":1,"ok":true,"agent":"builder-1","checkedAt":"2026-09-13T00:00:00Z"}`); err != nil {
		t.Fatalf("种子: %v", err)
	}
	_, first, _ := buildkeystore.NewAgentKey()
	_, second, _ := buildkeystore.NewAgentKey()
	register(t, s, first.PublicKey, "builder-1")
	register(t, s, second.PublicKey, "builder-2")

	c, recorder := testContext(t, platformTenantID, "POST", "/v1/admin/platform/build-agent/public-key/accept", map[string]any{
		"fingerprint": second.Fingerprint(), "reason": "换了打包机", "confirm": true,
	})
	c.Set("actorId", "tester")
	s.acceptBuildAgentKey(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("接受失败: %d %s", recorder.Code, recorder.Body.String())
	}
	check, err := s.keystoreCheckFor(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if check != nil {
		t.Fatalf("旧的验证结果还在，界面会拿它给新公钥背书：%+v", check)
	}
}
