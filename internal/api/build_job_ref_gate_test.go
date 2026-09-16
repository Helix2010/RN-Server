package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// buildJobDBServer 给认领测试一个连着测试库的服务端；没有 RN_TEST_MYSQL_DSN 时跳过。
// 认领路径只用到 db，配置留零值。
func buildJobDBServer(t *testing.T) *server {
	t.Helper()
	return &server{db: openTestDB(t)}
}

// 服务端不把库里那一列的 git_ref 下发出去（build-concurrency-2026-09-15.md §9）。
//
// 只要让打包机检出一个带后门的提交，构建时执行的就是攻击者的代码。打包机侧的
// validateGitRef 只挡形状（选项注入、路径穿越），一个形状完全合法的分支名它拦不住。
// 所以闸必须在服务端：不下发就不会被检出。
func TestDBClaimRefusesAJobWhoseGitRefWasTamperedWith(t *testing.T) {
	s := buildJobDBServer(t)
	ctx := context.Background()
	tenant := testTenant(51)
	now := time.Now().UTC()

	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO tenants(id,slug,status,start_date,expiry_date,deleted,created_at,updated_at)
		 VALUES(?,?,1,CURDATE(),DATE_ADD(CURDATE(), INTERVAL 1 YEAR),0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))`,
		tenant, "refgate-"+uniqueSuffix()); err != nil {
		t.Fatal(err)
	}
	// 队列是跨租户的，而且 claim 里的 reapStaleBuildJobs 会把心跳停了的旧任务
	// 重新入队——只删 queued 的不够。照 build_jobs_test.go 的做法清掉别人的
	if _, err := s.db.ExecContext(ctx, `DELETE FROM build_jobs WHERE tenant_id<>?`, tenant); err != nil {
		t.Fatal(err)
	}

	// 模拟「有人直接写了库」：形状完全合法的分支名，validateGitRef 拦不住
	jobID := "bj_" + uniqueSuffix()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO build_jobs(id,tenant_id,platform,git_ref,version,build_number,status,log_tail,reason,release_notes,created_by,created_at,updated_at)
		 VALUES(?,?,'android',?,'1.0.0',1,'queued','[]','test','{}','tester',?,?)`,
		jobID, tenant, "attacker-branch", now, now); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM build_jobs WHERE id=?`, jobID) })

	c, recorder := testContext(t, platformTenantID, "POST", "/v1/build-agent/build-jobs/claim",
		map[string]any{"agent": "builder-1", "platforms": []string{"android"}})
	s.claimBuildJob(c)
	// gin 的 c.Status() 是惰性写入的：直接调 handler（不过路由）时不 flush 就
	// 留在 recorder 默认的 200。仓库里其它 204 断言也是这么做的
	c.Writer.WriteHeaderNow()

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("被篡改的 ref 不该被下发，应当 204，得到 %d %s", recorder.Code, recorder.Body.String())
	}
	if body := recorder.Body.String(); body != "" {
		t.Errorf("被篡改的任务不能有任何内容下发给打包机，却回了: %s", body)
	}

	// 而且要判死，不能留在队列里——留着的话下一次认领还会撞上它，
	// 而队列是跨租户的，一条卡住的任务会把所有租户的构建堵死
	var status, reason string
	if err := s.db.QueryRowContext(ctx,
		`SELECT status, COALESCE(failure_reason,'') FROM build_jobs WHERE id=?`, jobID).
		Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Errorf("这条任务应当被判死，现在是 %q——留在队列里会堵死整个跨租户队列", status)
	}
	if reason == "" {
		t.Error("判死没写原因，事后没人查得出发生过什么")
	}
}

// 正常的任务（git_ref 就是固定分支）当然要能被认领。
// 没有这一条，上面那个闸可以靠「谁都不下发」通过，而那会让构建整个停摆
func TestDBClaimStillDispatchesAJobOnTheFixedBranch(t *testing.T) {
	s := buildJobDBServer(t)
	ctx := context.Background()
	tenant := testTenant(52)
	now := time.Now().UTC()

	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO tenants(id,slug,status,start_date,expiry_date,deleted,created_at,updated_at)
		 VALUES(?,?,1,CURDATE(),DATE_ADD(CURDATE(), INTERVAL 1 YEAR),0,UTC_TIMESTAMP(3),UTC_TIMESTAMP(3))`,
		tenant, "refok-"+uniqueSuffix()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM build_jobs WHERE tenant_id<>?`, tenant); err != nil {
		t.Fatal(err)
	}
	jobID := "bj_" + uniqueSuffix()
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO build_jobs(id,tenant_id,platform,git_ref,version,build_number,status,log_tail,reason,release_notes,created_by,created_at,updated_at)
		 VALUES(?,?,'android',?,'1.0.0',1,'queued','[]','test','{}','tester',?,?)`,
		jobID, tenant, buildGitRef, now, now); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.db.Exec(`DELETE FROM build_jobs WHERE id=?`, jobID) })

	c, recorder := testContext(t, platformTenantID, "POST", "/v1/build-agent/build-jobs/claim",
		map[string]any{"agent": "builder-1", "platforms": []string{"android"}})
	s.claimBuildJob(c)

	// 这里不把租户的 App 身份配全（那是另一条链路的事），所以认领可能停在
	// 409 APP_IDENTITY_INCOMPLETE。要证明的只有一件事：**它不是被 ref 闸挡下的**。
	// 判据看任务本身：被 ref 闸挡下会判死并写明原因
	var status, reason string
	if err := s.db.QueryRowContext(ctx,
		`SELECT status, COALESCE(failure_reason,'') FROM build_jobs WHERE id=?`, jobID).
		Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(reason, "refusing to build a git ref") {
		t.Errorf("固定分支上的任务被 ref 闸挡下了——那会让构建整个停摆: %s", reason)
	}
	if recorder.Code == http.StatusNoContent && status == "failed" {
		t.Errorf("固定分支上的任务被判死了: %s", reason)
	}
	// 它必须真的被选中过，否则上面两条断言在「根本没轮到它」时也会通过
	var claimedBy string
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(claimed_by,'') FROM build_jobs WHERE id=?`, jobID).Scan(&claimedBy); err != nil {
		t.Fatal(err)
	}
	if claimedBy == "" {
		t.Fatal("这条任务根本没被认领——这条测试什么都没证明")
	}
}
