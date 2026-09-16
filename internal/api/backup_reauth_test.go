package api

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"

	"golang.org/x/crypto/scrypt"

	"github.com/Helix2010/RN-Server/internal/config"
)

// 现算而不是硬编码一串哈希：硬编码的话，verifyPassword 的参数一改这里就是
// 一个查不出原因的失败
const testAdminPassword = "backup-test-password"

var testAdminPasswordHash = mustHashForTest(testAdminPassword)

func mustHashForTest(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	const n, r, p = 16384, 8, 1
	key, err := scrypt.Key([]byte(password), salt, n, r, p, 32)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("scrypt$%d$%d$%d$%s$%s", n, r, p,
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(key))
}

// 「跑一次」和「下载」要重新输一次口令（设计 §6 最后一段、§8.2、§8.6）。
//
// 控制台只有一个登录账号，平台管理员白名单实际等于「凡是能登录的人都看得见」，
// 而会话 TTL 默认 8 小时。没有这一道，一个被偷走的 cookie 在 8 小时内可以把桶里
// 每一条 succeeded 记录的包逐个拉走——每一个包都是全平台每个租户的签名密钥。
func TestDBBackupActionsRequireThePasswordAgain(t *testing.T) {
	// 先在**父测试**里取一次：没有 RN_TEST_MYSQL_DSN 时 backupServer 会 t.Skip()，
	// 而 Skip 是 runtime.Goexit。如果这件事发生在 t.Run 的子测试里、用的却是外层的
	// t，Go 会报「subtest may have called FailNow on a parent test」并让整个包 FAIL。
	// CI 上正是没有数据库的，所以这条不放在父测试里就是一次必然的红。
	backupServer(t)

	newServer := func(t *testing.T) *server {
		t.Helper()
		s := backupServer(t)
		s.cfg = config.Config{
			AdminPasswordHash: testAdminPasswordHash,
			Backup:            config.Backup{Bucket: config.BackupBucket{Bucket: "b"}},
		}
		return s
	}

	t.Run("跑一次：不给口令就拒绝", func(t *testing.T) {
		s := newServer(t)
		c, recorder := testContext(t, platformTenantID, "POST", "/x",
			map[string]any{"reason": "no password given", "confirm": true})
		s.runBackupNow(c)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("没有口令应当 403，得到 %d %s", recorder.Code, recorder.Body.String())
		}
	})

	t.Run("跑一次：口令错了就拒绝", func(t *testing.T) {
		s := newServer(t)
		c, recorder := testContext(t, platformTenantID, "POST", "/x",
			map[string]any{"reason": "wrong password", "confirm": true, "password": "nope"})
		s.runBackupNow(c)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("口令错了应当 403，得到 %d", recorder.Code)
		}
	})

	t.Run("连续猜错要被限速", func(t *testing.T) {
		s := newServer(t)
		var last int
		for i := 0; i < backupReauthMaxTries+1; i++ {
			c, recorder := testContext(t, platformTenantID, "POST", "/x",
				map[string]any{"reason": "guessing away", "confirm": true, "password": "nope"})
			s.runBackupNow(c)
			last = recorder.Code
		}
		if last != http.StatusTooManyRequests {
			t.Errorf("猜了 %d 次还没被限速（最后 %d）——口令是这道补偿的全部内容，"+
				"不限速等于让拿到 cookie 的人随便猜", backupReauthMaxTries+1, last)
		}
	})

	t.Run("没配口令哈希时拒绝而不是放行", func(t *testing.T) {
		s := backupServer(t)
		s.cfg = config.Config{Backup: config.Backup{Bucket: config.BackupBucket{Bucket: "b"}}}
		c, recorder := testContext(t, platformTenantID, "POST", "/x",
			map[string]any{"reason": "no hash configured", "confirm": true, "password": "x"})
		s.runBackupNow(c)
		if recorder.Code != http.StatusPreconditionFailed {
			t.Errorf("没配哈希时静默放行等于这道闸不存在，得到 %d", recorder.Code)
		}
	})
}

// 票据：一次性、绑定 seq+pair+操作者、两分钟过期。
func TestBackupDownloadTicketIsSingleUseAndBound(t *testing.T) {
	r := &backupReauth{}
	token := r.issue(7, "AB", "ops")

	if r.redeem(token, 7, "AC", "ops") {
		t.Error("票据能换到别的组合的包")
	}
	if r.redeem(token, 8, "AB", "ops") {
		t.Error("票据能换到别的 seq 的包")
	}
	token = r.issue(7, "AB", "ops")
	if r.redeem(token, 7, "AB", "someone-else") {
		t.Error("票据能被别的操作者用掉")
	}

	token = r.issue(7, "AB", "ops")
	if !r.redeem(token, 7, "AB", "ops") {
		t.Fatal("正确的票据应当能用")
	}
	if r.redeem(token, 7, "AB", "ops") {
		t.Error("同一张票据用了第二次——链接被复制之后就能反复下载")
	}
}
