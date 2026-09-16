package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/backupbundle"
	"github.com/Helix2010/RN-Server/internal/backupcontainer"
	"github.com/gin-gonic/gin"
)

func signingKeyServer(t *testing.T) *server {
	t.Helper()
	db := openTestDB(t)
	if _, err := db.Exec(`DELETE FROM app_configs WHERE tenant_id=? AND config_key=?`,
		platformTenantID, backupSigningKeyConfigKey); err != nil {
		t.Fatalf("清掉上一轮的登记: %v", err)
	}
	return &server{db: db}
}

func newSigningPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := backupcontainer.EncodeSigningPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func registerSigning(t *testing.T, s *server, publicKey, agent string) map[string]any {
	t.Helper()
	c, recorder := testContext(t, platformTenantID, "POST", "/v1/build-agent/backup-signing-key", map[string]any{
		"publicKey": publicKey, "agent": agent,
	})
	s.registerBackupSigningKey(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("登记失败: %d %s", recorder.Code, recorder.Body.String())
	}
	return decodeBody(t, recorder)
}

// 和 X25519 那把同一套规则：第一把直接定下来，换钥匙必须人确认。
//
// 自动接受等于偷到代理令牌的人换掉签名公钥，此后他伪造的备份包全都验得过
// ——而验签正是「连服务端一起被攻破也还成立」的那条防线
func TestDBBackupSigningKeyIsPinnedAfterTheFirstRegistration(t *testing.T) {
	s := signingKeyServer(t)
	first, second := newSigningPublicKey(t), newSigningPublicKey(t)

	if out := registerSigning(t, s, first, "builder-1"); out["status"] != "registered" {
		t.Fatalf("第一把应当直接登记：%v", out)
	}
	if out := registerSigning(t, s, first, "builder-1"); out["status"] != "unchanged" {
		t.Fatalf("重报同一把不该有动静：%v", out)
	}
	if out := registerSigning(t, s, second, "builder-2"); out["status"] != "pending_acceptance" {
		t.Fatalf("换签名公钥必须挂起等人确认：%v", out)
	}
	record, err := s.backupSigningKeyRecord(context.Background())
	if err != nil || record == nil {
		t.Fatal(err)
	}
	if record.Current.PublicKey != first {
		t.Fatal("没人确认，正在用的签名公钥却被换掉了")
	}
	if record.Pending == nil || record.Pending.PublicKey != second {
		t.Fatalf("新公钥没有被记成待确认：%+v", record.Pending)
	}
}

// 接受换钥匙时，旧的那把必须进 Previous 而不是被删掉。
//
// 桶里的历史包是旧那把签的。删掉就等于把它们变成验不了签的废物——而恢复时
// 你可能正好要用其中一个
func TestDBAcceptingANewSigningKeyKeepsTheOldOneForHistoricalPackages(t *testing.T) {
	s := signingKeyServer(t)
	first, second := newSigningPublicKey(t), newSigningPublicKey(t)
	registerSigning(t, s, first, "builder-1")
	firstFingerprint := registerSigning(t, s, first, "builder-1")["fingerprint"]
	registerSigning(t, s, second, "builder-2")

	record, err := s.backupSigningKeyRecord(context.Background())
	if err != nil || record == nil || record.Pending == nil {
		t.Fatal("待确认的那把不见了")
	}
	c, recorder := testContext(t, platformTenantID, "POST", "/v1/admin/platform/backup/signing-key/accept",
		map[string]any{"fingerprint": record.Pending.Fingerprint, "reason": "rebuilt the build machine", "confirm": true})
	s.acceptBackupSigningKey(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("接受失败: %d %s", recorder.Code, recorder.Body.String())
	}

	record, err = s.backupSigningKeyRecord(context.Background())
	if err != nil || record == nil {
		t.Fatal(err)
	}
	if record.Current.PublicKey != second {
		t.Fatal("接受之后正在用的不是新那把")
	}
	if record.Pending != nil {
		t.Fatal("接受之后 pending 应该清空")
	}
	if len(record.Previous) != 1 || record.Previous[0].Fingerprint != firstFingerprint {
		t.Fatalf("旧签名公钥必须留档，否则历史备份包永远验不了签：%+v", record.Previous)
	}
	if record.Previous[0].At == "" {
		t.Fatal("留档要带退役时间，否则看不出哪个包对应哪把钥匙")
	}
}

// 指纹对不上就拒绝：这是「你确实核对过那台机器上是哪一把」的唯一证据
func TestDBAcceptRefusesAMismatchedFingerprint(t *testing.T) {
	s := signingKeyServer(t)
	registerSigning(t, s, newSigningPublicKey(t), "builder-1")
	registerSigning(t, s, newSigningPublicKey(t), "builder-2")

	c, recorder := testContext(t, platformTenantID, "POST", "/v1/admin/platform/backup/signing-key/accept",
		map[string]any{"fingerprint": "0000", "reason": "looks fine to me", "confirm": true})
	s.acceptBackupSigningKey(c)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("指纹对不上必须拒绝，得到 %d", recorder.Code)
	}
}

// 非 Ed25519 / 非 DER SPKI 的值要在入口就拒掉，不能存进库里等到用的时候才炸
func TestDBRegisterRefusesAKeyItCannotUse(t *testing.T) {
	s := signingKeyServer(t)
	for _, bad := range []string{"not base64!", "aGVsbG8=", ""} {
		c, recorder := testContext(t, platformTenantID, "POST", "/v1/build-agent/backup-signing-key",
			map[string]any{"publicKey": bad, "agent": "builder-1"})
		s.registerBackupSigningKey(c)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%q 应当被拒绝，得到 %d", bad, recorder.Code)
		}
	}
	record, err := s.backupSigningKeyRecord(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if record != nil {
		t.Fatal("被拒绝的值不该留下任何记录")
	}
}

// 换过机器之后，打包机会报上来一把新的签名公钥，而 current 不动——控制台必须
// 看得见这件事。看不见的话，人看到的是一切正常的旧指纹，而每一次备份都在失败，
// 报「register it first」，而控制台上根本没有 register 的入口。
func TestDBBackupStatusShowsAPendingKeyWaitingToBeAccepted(t *testing.T) {
	s := backupServer(t)
	if err := s.saveBackupSigningKey(context.Background(), backupSigningKeyRecord{
		Current: backupSigningKey{PublicKey: "old", Fingerprint: strings.Repeat("a", 64)},
		Pending: &backupSigningKey{PublicKey: "new", Fingerprint: strings.Repeat("b", 64),
			Agent: "amos-builder-1", At: "2026-09-16T00:00:00Z"},
	}, "tester"); err != nil {
		t.Fatal(err)
	}

	c, recorder := testContext(t, platformTenantID, "GET", "/x", nil)
	s.getBackupStatus(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("读状态应当成功: %d %s", recorder.Code, recorder.Body.String())
	}
	var view struct {
		SigningKey struct {
			Fingerprint string `json:"fingerprint"`
			Pending     *struct {
				Fingerprint string  `json:"fingerprint"`
				Agent       *string `json:"agent"`
			} `json:"pending"`
		} `json:"signingKey"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.SigningKey.Fingerprint != strings.Repeat("a", 64) {
		t.Errorf("current 不该被 pending 顶掉: %+v", view.SigningKey)
	}
	if view.SigningKey.Pending == nil || view.SigningKey.Pending.Fingerprint != strings.Repeat("b", 64) {
		t.Fatalf("待接受的那把没有回给控制台: %+v", view.SigningKey.Pending)
	}
	if view.SigningKey.Pending.Agent == nil || *view.SigningKey.Pending.Agent != "amos-builder-1" {
		t.Errorf("没说是哪台机器报上来的，人不知道该去哪核对: %+v", view.SigningKey.Pending)
	}
}

// 读不到登记记录不是「指纹不对」。
//
// 2026-09-16 第一次真实备份：打包机传 body 用了 18 秒，请求上那 10 秒的数据库超时早过了，
// 查登记记录拿到 context deadline exceeded，却回了 409「签名指纹不是登记的那把」——
// 人会去核对一把根本没换过的钥匙
func TestDBSigningKeyLookupFailureIsNotReportedAsAMismatch(t *testing.T) {
	s := backupServer(t)
	run := mustCreate(t, s, "lookup fails")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c, recorder := testContext(t, platformTenantID, "POST", "/x", nil)
	meta := backupbundle.PayloadMeta{BackupSigningFingerprint: strings.Repeat("a", 64)}
	if err := s.checkBackupSigningFingerprint(ctx, c, run, meta); err == nil {
		t.Fatal("查库失败时不能放行")
	}
	body := decodeBody(t, recorder)
	if recorder.Code != http.StatusInternalServerError || body["code"] != "BACKUP_SIGNING_KEY_QUERY_FAILED" {
		t.Fatalf("查库失败要如实报，不能冒充指纹不匹配: %d %v", recorder.Code, body)
	}
	if again, err := s.backupRunByID(context.Background(), run.ID); err != nil || again.Status != run.Status {
		t.Fatalf("查库失败不该判死记录: %+v %v", again, err)
	}
}

// 上传备份内层的那条路由不能套请求级的数据库超时：body 传得比它久，后面每次查库都失败
func TestDatabaseTimeoutDoesNotWrapTheBackupPayloadUpload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	s := &server{}
	s.cfg.MySQLQueryTimeout = 1
	for path, wantDeadline := range map[string]bool{
		"/v1/build-agent/backup-requests/pbk_1/payload": false,
		"/v1/build-agent/backup-requests/claim":         true,
	} {
		router := gin.New()
		router.Use(s.databaseTimeout())
		router.POST(path, func(c *gin.Context) {
			_, hasDeadline := c.Request.Context().Deadline()
			c.JSON(http.StatusOK, gin.H{"hasDeadline": hasDeadline})
		})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if want := fmt.Sprintf(`{"hasDeadline":%t}`, wantDeadline); response.Body.String() != want {
			t.Errorf("%s: 想要 %s，得到 %s", path, want, response.Body.String())
		}
	}
}
