package main

import (
	"context"
	"net/http"
	"os"
	"regexp"
	"testing"
	"time"
)

func serveWithTimeout(t *testing.T, a *agent, within time.Duration) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	return a.serve(ctx)
}

// 吊销码不能和"配置不全"的 2 混用：rn-foundation-apply 的冒烟靠 2；unit 必须阻止对它重启
func TestRevokedExitStatusIsDistinctAndNotRestarted(t *testing.T) {
	if exitMachineRevoked == 2 || exitMachineRevoked == 0 {
		t.Fatalf("exitMachineRevoked = %d", exitMachineRevoked)
	}
	unit, err := os.ReadFile("../../deploy/build-agent/rn-build-agent.service")
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`(?m)^RestartPreventExitStatus=(\d+)\s*$`).FindSubmatch(unit)
	if match == nil || string(match[1]) != "77" || exitMachineRevoked != 77 {
		t.Fatalf("the unit does not prevent restarts for the revoked exit status %d", exitMachineRevoked)
	}
}

// 在跑的构建中途被吊销（心跳先撞上）：立刻中止、清理、不再上报，常驻循环以 77 退出
func TestRevocationDuringABuildAbortsAndExits(t *testing.T) {
	rig := newRig(t)
	if err := os.WriteFile(rig.tools.Sleep, []byte(neverFinishesSeconds), 0o644); err != nil {
		t.Fatal(err)
	}
	rig.server.failOnce("/heartbeat", http.StatusUnauthorized, codeMachineRevoked)
	rig.server.queueClaim(claimBody("bld_revokedJOB01", "apk"))

	// 没被中止的话假构建要睡 neverFinishesSeconds 秒，serve 会等到上限到期才以 0 返回
	if code := serveWithTimeout(t, rig.agent, loadIndependentBound); code != exitMachineRevoked {
		t.Fatalf("serve returned %d, want %d", code, exitMachineRevoked)
	}
	for _, suffix := range []string{"/fail", "/built", "/unsigned/upload", "/complete"} {
		if calls := rig.server.callsTo(suffix); len(calls) != 0 {
			t.Fatalf("a revoked machine still called %s", suffix)
		}
	}
	if left := jobRootEntries(t, rig.agent); len(left) != 0 {
		t.Fatalf("job directories left behind: %v", left)
	}
}

// 交付上传撞上吊销：同样不报失败、不交付
func TestRevocationDuringDeliveryIsNotReported(t *testing.T) {
	rig := newRig(t)
	rig.server.failOnce("/unsigned/upload", http.StatusUnauthorized, codeMachineRevoked)
	rig.server.queueClaim(claimBody("bld_revokedJOB02", "apk"))
	if code := serveWithTimeout(t, rig.agent, loadIndependentBound); code != exitMachineRevoked {
		t.Fatalf("serve returned %d", code)
	}
	if len(rig.server.callsTo("/fail")) != 0 || len(rig.server.callsTo("/built")) != 0 {
		t.Fatal("a revoked machine reported the job")
	}
	if left := jobRootEntries(t, rig.agent); len(left) != 0 {
		t.Fatalf("job directories left behind: %v", left)
	}
}

// 公钥登记就收到 MACHINE_REVOKED：不领任务，直接退出
func TestRevokedAtRegistrationExits(t *testing.T) {
	rig := newRig(t)
	rig.server.setAuthCode(codeMachineRevoked)
	rig.server.queueClaim(claimBody("bld_neverClaimed", "apk"))
	if code := serveWithTimeout(t, rig.agent, loadIndependentBound); code != exitMachineRevoked {
		t.Fatalf("serve returned %d", code)
	}
	if len(rig.server.callsTo("/claim")) != 0 {
		t.Fatal("a revoked machine claimed")
	}
}

// 登记成功过之后令牌不再被认（MACHINE_AUTH_REQUIRED）：按吊销处理
func TestAuthRequiredAfterRegistrationMeansRevoked(t *testing.T) {
	rig := newRig(t)
	if rig.agent.pollOnce(context.Background()) {
		t.Fatal("an empty queue was reported as work")
	}
	rig.server.setAuthCode(codeMachineAuthRequired)
	rig.agent.keyActive = false
	if code := serveWithTimeout(t, rig.agent, loadIndependentBound); code != exitMachineRevoked {
		t.Fatalf("serve returned %d", code)
	}
}

// 登记之前就收到 MACHINE_AUTH_REQUIRED（多半是令牌抄错）：不算吊销，照常等，停机信号时以 0 退出
func TestAuthRequiredBeforeRegistrationKeepsWaiting(t *testing.T) {
	rig := newRig(t)
	rig.server.setAuthCode(codeMachineAuthRequired)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	// 至少让它撞上两次 401 之后再发停机信号，否则断言可能什么都没验
	go func() {
		defer stop()
		// 不能在这个 goroutine 里 t.Fatal：等不到就照样停，由下面的断言报出来
		deadline := time.Now().Add(loadIndependentBound)
		for len(rig.server.callsTo("/public-key")) < 2 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	}()
	if code := rig.agent.serve(ctx); code != 0 {
		t.Fatalf("serve returned %d, want 0 after the stop signal", code)
	}
	if rig.agent.api.isRevoked() {
		t.Fatal("an unrecognised token before any registration was treated as a revocation")
	}
	if n := len(rig.server.callsTo("/public-key")); n < 2 {
		t.Fatalf("only %d key registrations were attempted before stopping", n)
	}
}
