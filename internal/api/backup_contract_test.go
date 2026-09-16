package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/backupbundle"
	"github.com/gin-gonic/gin"
)

// 设计 §8.1 明确要求「不能复用 /keystore-checks」：它 LIMIT 20 且跳过
// 「这一版已验过」的租户。拿它做备份会静默漏租户，而漏掉的那个租户的签名密钥
// 就此**永远没有离线副本**——而且没有任何人会发现，直到那台机器坏了。
//
// 所以造 25 个租户，断言备份接口一个不落。这条测试防的是「有人figure出
// 复用现成接口更省事」那一天。
func TestDBBackupKeystoresReturnsEveryTenantNotJustTwenty(t *testing.T) {
	s := advServer(t)
	ctx := context.Background()
	const tenants = 25
	ids := make([]string, 0, tenants)
	for i := 0; i < tenants; i++ {
		id := fmt.Sprintf("9500000%04d", i)
		ids = append(ids, id)
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO app_configs(tenant_id,config_key,config_value,version,updated_by,updated_at)
			 VALUES(?,?,'{"sealed":"x","keyAlias":"a"}',1,'test',UTC_TIMESTAMP(3))
			 ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)`,
			id, buildKeystoreConfigKey); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, id := range ids {
			_, _ = s.db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`,
				id, buildKeystoreConfigKey)
		}
	})

	run := advClaimed(t, s, "every tenant must be in the package")
	c, recorder := testContext(t, platformTenantID, "GET",
		"/v1/build-agent/backup-keystores?request="+run.ID, nil)
	c.Request.URL.RawQuery = "request=" + run.ID
	s.backupKeystores(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("认领之后应当能拉到盒子: %d %s", recorder.Code, recorder.Body.String())
	}
	// 这个环境里解不开盒子（没有 master key），所以 items 会是空的——
	// 但接口**枚举**了多少租户才是这条测试的判据。用日志之外的方式看不到，
	// 所以直接查一遍它枚举的那条 SQL，确认没有 LIMIT
	var counted int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM app_configs WHERE config_key=?`, buildKeystoreConfigKey).Scan(&counted); err != nil {
		t.Fatal(err)
	}
	if counted < tenants {
		t.Fatalf("测试夹具没建够租户: %d", counted)
	}
	// 直接读源码断言那条枚举语句没有 LIMIT。绕，但它守的东西很硬：
	// 漏掉的租户的签名密钥就此永远没有离线副本，而没有任何人会发现
	source, err := os.ReadFile("backup_agent.go")
	if err != nil {
		t.Fatal(err)
	}
	query := string(source)
	start := strings.Index(query, "SELECT tenant_id, version FROM app_configs WHERE config_key=?")
	if start < 0 {
		t.Fatal("找不到备份用的枚举语句——它被改过了，这条测试要跟着改")
	}
	if strings.Contains(query[start:start+200], "LIMIT") {
		t.Fatal("备份用的枚举语句带了 LIMIT——漏掉的租户的签名密钥就此永远没有离线副本")
	}
}

// 门禁判据是「这个 id 下有一条 running 的待办」。直接造一条 pending 行再调接口
// 必须 403——v5 写的是「有 pending 时才返回」，那和状态机自相矛盾：认领那一刻
// 就变 running 了，于是每一次备份都拿不到盒子，而测试因为不经过认领会绿
func TestDBBackupKeystoresRequiresAClaimedRequest(t *testing.T) {
	s := advServer(t)
	run := mustCreate(t, s, "not claimed yet")

	c, recorder := testContext(t, platformTenantID, "GET", "/v1/build-agent/backup-keystores", nil)
	c.Request.URL.RawQuery = "request=" + run.ID
	s.backupKeystores(c)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("没认领就拉盒子必须 403，得到 %d %s", recorder.Code, recorder.Body.String())
	}

	// 不存在的 id 也是 403 而不是 404：这个接口一次给出全平台的密封盒子，
	// 不该让人用它探测 id 是否存在
	c, recorder = testContext(t, platformTenantID, "GET", "/v1/build-agent/backup-keystores", nil)
	c.Request.URL.RawQuery = "request=pbk_does_not_exist"
	s.backupKeystores(c)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("不存在的 id 应当 403（不泄露存在性），得到 %d", recorder.Code)
	}
}

// 同一槽位传两次是**正常重试**撞上已经收到的那一份，不是请求有错。
// 409 让打包机知道不用再传，而第一次的记录不受影响
func TestDBUploadingTheSameSlotTwiceIsAConflictNotACorruption(t *testing.T) {
	s := advServer(t)
	run := advClaimed(t, s, "duplicate slot")

	first := advPost(t, s, run.ID, []backupbundle.PayloadMeta{advMeta("A")}, []byte("first"))
	if first.Code != http.StatusAccepted {
		t.Fatalf("第一份应当 202，得到 %d %s", first.Code, first.Body.String())
	}
	second := advPost(t, s, run.ID, []backupbundle.PayloadMeta{advMeta("A")}, []byte("second"))
	if second.Code != http.StatusConflict {
		t.Fatalf("同一槽位重复传应当 409，得到 %d %s", second.Code, second.Body.String())
	}
	// 第一份必须完好：重复的那次不能把它覆盖掉
	if missing := missingInnerSlots(backupStagingDir(run.ID)); len(missing) != 1 || missing[0] != "B" {
		t.Fatalf("第一份应当还在，只差 B，得到 %v", missing)
	}
}

// 打包机换了签名密钥而没走登记流程，是个**必须让人看见**的信号：
// 此后它产出的包，持有人拿登记在案的公钥验不过
func TestDBASigningFingerprintMismatchFailsTheBackupWithAReadableReason(t *testing.T) {
	s := advServer(t)
	run := advClaimed(t, s, "signing key drifted")

	meta := advMeta("A")
	meta.BackupSigningFingerprint = "0000000000000000000000000000000000000000000000000000000000000000"
	recorder := advPost(t, s, run.ID, []backupbundle.PayloadMeta{meta}, []byte("payload"))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("签名公钥对不上应当 409，得到 %d %s", recorder.Code, recorder.Body.String())
	}
	after, err := s.backupRunByID(context.Background(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != backupStatusFailed {
		t.Fatalf("这条待办应当直接判死，得到 %s", after.Status)
	}
	if after.FailureReason == "" {
		t.Fatal("判死要带可读原因，否则运维不知道是签名密钥的事")
	}
}

// 换掉一个槽位的公钥之后，**旧记录一个字都不该动**。
// 控制台按每条记录自己的 objects 渲染，不按当前配置——否则换过公钥之后，
// 界面会告诉你一个老包要用新钥匙开
func TestDBRotatingARecoveryKeyLeavesOldRecordsUntouched(t *testing.T) {
	s := advServer(t)
	ctx := context.Background()
	old := mustCreate(t, s, "before rotation")
	if _, _, err := s.claimBackupRun(ctx, "builder"); err != nil {
		t.Fatal(err)
	}
	oldObjects := []backupObject{
		{Pair: "AB", ObjectKey: "k/ab", SHA256: "aa", SizeBytes: 1},
		{Pair: "AC", ObjectKey: "k/ac", SHA256: "bb", SizeBytes: 1},
		{Pair: "BC", ObjectKey: "k/bc", SHA256: "cc", SizeBytes: 1},
	}
	if _, err := s.finishBackupRun(ctx, old.ID, oldObjects, 3); err != nil {
		t.Fatal(err)
	}

	// 换公钥 = 改 env = 换一份 cfg。老记录不经过任何写路径
	s.cfg.Backup.Recipients[2].Fingerprint = "rotated"

	after, err := s.backupRunByID(ctx, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Objects) != 3 {
		t.Fatalf("老记录的 objects 应当原封不动，得到 %d 组", len(after.Objects))
	}
	for i, object := range after.Objects {
		if object.SHA256 != oldObjects[i].SHA256 || object.ObjectKey != oldObjects[i].ObjectKey {
			t.Fatalf("老记录被改写了: %+v", object)
		}
	}
	// 控制台的渲染也必须按这一条自己的 objects 走
	view := backupRunView(after)
	if len(view["objects"].([]gin.H)) != 3 {
		t.Fatal("控制台应当按这条记录自己产出的那几组渲染")
	}
}
