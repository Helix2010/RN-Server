package signer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/apk/apktest"
	"github.com/Helix2010/RN-Server/signing/internal/testfixture"
	"github.com/Helix2010/RN-Server/signing/records"
	"github.com/Helix2010/RN-Server/signing/trustroots"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func slogTo(w io.Writer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }

func TestHappyPathSignsDeliversAndRecords(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	b := h.build("bld_happyJOB00000001", 46, nil)
	h.enqueue(b, 1, nil)
	if !h.runOnce() {
		t.Fatalf("no job was processed; logs:\n%s", h.logs.String())
	}
	s := h.server
	// 试解、确认、试签都上报了，并据此认领
	if len(s.reports) != 1 || len(s.reports[0]) != 1 {
		t.Fatalf("reports: %+v", s.reports)
	}
	rep := s.reports[0][0]
	if rep.Decrypt != "ok" || !rep.Confirmed || rep.ConfirmedTrustRootsDigest == nil || *rep.ConfirmedTrustRootsDigest != h.digest || rep.TrialSign != "ok" || rep.Error != nil {
		t.Fatalf("check report: %+v", rep)
	}
	if len(s.claimBodies) != 1 || len(s.claimBodies[0]) != 1 || s.claimBodies[0][0] != (ReadyItem{testfixture.TenantSlug, testfixture.PackageName, h.key.CertificateSHA256, h.digest}) {
		t.Fatalf("claim ready list: %+v", s.claimBodies)
	}
	if len(s.completes) != 1 || len(s.rejects) != 0 || len(s.releases) != 0 {
		t.Fatalf("completes %d rejects %+v releases %+v; logs:\n%s", len(s.completes), s.rejects, s.releases, h.logs.String())
	}
	c := s.completes[0]
	uploaded := s.uploads[b.JobID]
	if c.SignedSHA256 != sha(uploaded) || c.CertificateSHA256 != h.key.CertificateSHA256 || c.UnsignedSHA256 != b.SHA256 || c.NativeFingerprint != apktest.DefaultNativeFingerprint {
		t.Fatalf("complete body: %+v", c)
	}
	// 试签一次 + 正式签一次
	if h.signer.signCount() != 2 {
		t.Fatalf("sign calls: %d", h.signer.signCount())
	}
	list, _ := h.store.Reservations()
	if len(list) != 1 || list[0].Status != records.StatusCompleted || list[0].ReleaseID != testReleaseID || list[0].SignedSHA256 != c.SignedSHA256 || list[0].VersionCode != 46 {
		t.Fatalf("local record: %+v", list)
	}
	h.assertRuntimeEmpty()
}

func TestDeferredIsNotAViolation(t *testing.T) {
	t.Run("certificate not confirmed", func(t *testing.T) {
		h := newHarness(t, harnessOptions{noConfirm: true})
		b := h.build("bld_deferJOB00000001", 46, nil)
		// 本机没确认时不会报就绪，服务端也不该派；这里模拟服务端照派不误
		h.runner.setReady([]ReadyItem{{TenantSlug: "AnyFun", PackageName: testfixture.PackageName, CertificateSHA256: h.key.CertificateSHA256, TrustRootsDigest: h.digest}})
		h.runner.lastChecks = time.Now()
		h.enqueue(b, 1, nil)
		h.runOnce()
		assertOutcome(t, h, "", "CERTIFICATE_NOT_CONFIRMED")
		if h.signer.signCount() != 0 {
			t.Fatal("signed without a confirmation")
		}
	})
	t.Run("trust roots changed since confirmation", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		b := h.build("bld_deferJOB00000002", 46, nil)
		other := h.roots
		other.APIBaseURL = "https://api2.anyfun.win"
		otherDigest, _ := trustroots.Digest(other)
		h.enqueue(b, 1, func(c map[string]any) { c["trustRoots"], c["trustRootsDigest"] = other, otherDigest })
		h.runOnce()
		assertOutcome(t, h, "", "TRUST_ROOTS_NOT_CONFIRMED")
	})
	t.Run("standby never claims", func(t *testing.T) {
		h := newHarness(t, harnessOptions{role: records.RoleStandby})
		h.enqueue(h.build("bld_deferJOB00000003", 46, nil), 1, nil)
		if h.runOnce() {
			t.Fatal("a standby processed a job")
		}
		if len(h.server.claimBodies) != 0 {
			t.Fatal("a standby called claim")
		}
		// 备照样试解、确认、试签并上报
		if len(h.server.reports) != 1 || h.server.reports[0][0].TrialSign != "ok" {
			t.Fatalf("standby reports: %+v", h.server.reports)
		}
	})
	t.Run("server roots differ so the tenant is not ready", func(t *testing.T) {
		h := newHarness(t, harnessOptions{serverRoots: func(r *trustroots.Roots) { r.Scheme = "anyfun2" }})
		h.enqueue(h.build("bld_deferJOB00000004", 46, nil), 1, nil)
		if h.runOnce() || len(h.server.claimBodies) != 0 || len(h.runner.Ready()) != 0 {
			t.Fatal("claimed while the server's trust roots differ from the confirmed ones")
		}
		rep := h.server.reports[0][0]
		if !rep.Confirmed || rep.TrialSign != "ok" {
			t.Fatalf("report: %+v", rep)
		}
	})
}

func TestViolationsAreRejectedBeforeDecryption(t *testing.T) {
	t.Run("package points at another server", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		b := h.build("bld_violJOB000000001", 46, func(s *apktest.Spec) {
			s.AppConfig["extra"].(map[string]any)["apiBaseUrl"] = "https://api.evil.example"
		})
		h.enqueue(b, 1, nil)
		h.runOnce()
		assertOutcome(t, h, "violation", "TRUST_ROOT_MISMATCH")
		if h.signer.signCount() != 1 { // 只有试签
			t.Fatal("the job reached signing")
		}
		if list, _ := h.store.Reservations(); len(list) != 0 {
			t.Fatal("a rejected package was reserved")
		}
		h.assertRuntimeEmpty()
	})
	t.Run("download does not match the job sha256", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		b := h.build("bld_violJOB000000002", 46, nil)
		h.enqueue(b, 1, nil)
		h.server.apks[b.JobID] = h.build("bld_violJOB000000002", 46, func(s *apktest.Spec) { s.VersionName = "9.9.9" }).APK
		h.runOnce()
		assertOutcome(t, h, "violation", "UNSIGNED_SIZE_MISMATCH", "UNSIGNED_SHA256_MISMATCH")
	})
	t.Run("builder forged in the database", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		forged := testfixture.NewBuilder(t)
		b := testfixture.NewBuild(t, forged, "bld_violJOB000000003", 46, nil)
		h.enqueue(b, 1, nil)
		h.runOnce()
		assertOutcome(t, h, "violation", "BUILDER_KEY_MISMATCH")
	})
	t.Run("keystore swapped on the server", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		b := h.build("bld_violJOB000000004", 46, nil)
		// 服务端把密文换成另一把 key 的（同样加密给本机），并把登记的指纹一起换掉
		other := h.sealBox(testfixture.TenantSlug, testfixture.PackageName, testfixture.Hex64('e'))
		h.enqueue(b, 1, func(c map[string]any) {
			ks := c["keystore"].(map[string]any)
			ks["box"], ks["certificateSha256"] = other, testfixture.Hex64('e')
		})
		h.runOnce()
		assertOutcome(t, h, "", "CERTIFICATE_NOT_CONFIRMED")
		// 指纹不换、只换密文：解开后身份不符，违规
		h.enqueue(b, 2, func(c map[string]any) { c["keystore"].(map[string]any)["box"] = other })
		h.runOnce()
		assertOutcome(t, h, "violation", "KEYSTORE_IDENTITY_MISMATCH")
	})
	t.Run("malformed claim", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		b := h.build("bld_violJOB000000005", 46, nil)
		h.enqueue(b, 1, func(c map[string]any) { c["job"].(map[string]any)["tenantSlug"] = "Any\x1b[2JFun" })
		h.runOnce()
		assertOutcome(t, h, "violation", "CLAIM_INVALID")
		if strings.Contains(h.server.rejects[0].Detail, "\x1b") {
			t.Fatal("the rejection detail echoes a control character")
		}
	})
}

func TestReservationAndIdempotentResign(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	b := h.build("bld_idemJOB000000001", 46, nil)
	h.enqueue(b, 1, nil)
	h.runOnce()
	if len(h.server.completes) != 1 {
		t.Fatalf("first run did not complete; logs:\n%s", h.logs.String())
	}
	first := h.server.completes[0]

	// 服务端回收后同一任务、同一输入包再次派下来：幂等重签，已签名包逐字节相同
	h.enqueue(b, 2, nil)
	h.runOnce()
	if len(h.server.completes) != 2 || h.server.completes[1] != first || len(h.server.rejects) != 0 {
		t.Fatalf("idempotent re-sign: completes %+v rejects %+v", h.server.completes, h.server.rejects)
	}
	if list, _ := h.store.Reservations(); len(list) != 1 {
		t.Fatalf("re-sign wrote a second reservation: %+v", list)
	}

	// 同一任务换了输入包：永久拒签
	changed := h.build("bld_idemJOB000000001", 46, func(s *apktest.Spec) {
		s.ExtraEntries = append(s.ExtraEntries, apktest.File{Name: "assets/other.txt", Data: []byte("x")})
	})
	h.enqueue(changed, 3, nil)
	h.runOnce()
	assertOutcome(t, h, "violation", "RESERVATION_CONFLICT")

	// 另一个任务用同一个 versionCode：不大于已签最大值
	h.enqueue(h.build("bld_idemJOB000000002", 46, nil), 1, nil)
	h.runOnce()
	assertOutcome(t, h, "violation", "VERSION_CODE_NOT_INCREASING")

	// 下一个版本照常签
	h.enqueue(h.build("bld_idemJOB000000003", 47, nil), 1, nil)
	h.runOnce()
	if len(h.server.completes) != 3 {
		t.Fatalf("next version was not signed; rejects %+v", h.server.rejects)
	}
	h.assertRuntimeEmpty()
}

func TestTransientFailures(t *testing.T) {
	t.Run("complete retried in place", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		b := h.build("bld_tranJOB000000001", 46, nil)
		h.server.completeFails[b.JobID] = []int{503, 500}
		h.enqueue(b, 1, nil)
		h.runOnce()
		if len(h.server.completes) != 1 || len(h.server.rejects) != 0 {
			t.Fatalf("completes %d rejects %+v", len(h.server.completes), h.server.rejects)
		}
	})
	t.Run("complete keeps failing", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		b := h.build("bld_tranJOB000000002", 46, nil)
		h.server.completeFails[b.JobID] = []int{503, 503, 503}
		h.enqueue(b, 1, nil)
		h.runOnce()
		assertOutcome(t, h, "transient", "COMPLETE_FAILED")
		list, _ := h.store.Reservations()
		if len(list) != 1 || list[0].Status != records.StatusReserved {
			t.Fatalf("the reservation must stay open for an idempotent retry: %+v", list)
		}
	})
	t.Run("server refuses the signed package", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		b := h.build("bld_tranJOB000000003", 46, nil)
		h.server.completeFails[b.JobID] = []int{422}
		h.enqueue(b, 1, nil)
		h.runOnce()
		assertOutcome(t, h, "violation", "SERVER_REJECTED_SIGNED_PACKAGE")
	})
	t.Run("apksigner fails", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		h.runner.RunChecks(context.Background()) // 先让试签成功
		h.signer.failSign = errors.New("apksigner exploded")
		h.enqueue(h.build("bld_tranJOB000000004", 46, nil), 1, nil)
		h.runOnce()
		assertOutcome(t, h, "transient", "APKSIGNER_FAILED")
		h.assertRuntimeEmpty()
	})
}

func TestStaleAttemptAbandonsImmediately(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.runner.RunChecks(context.Background())
	b := h.build("bld_staleJOB00000001", 46, nil)
	h.signer.block = make(chan struct{})
	h.enqueue(b, 1, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.runOnce()
	}()
	// 等签名开始，再让服务端宣布编号过期
	deadline := time.Now().Add(5 * time.Second)
	for h.signer.signCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	h.server.mu.Lock()
	h.server.staleJobs[b.JobID] = true
	h.server.mu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the signer kept working on a stale attempt")
	}
	if len(h.server.rejects) != 0 || len(h.server.releases) != 0 || len(h.server.completes) != 0 {
		t.Fatalf("reported on a stale attempt: rejects %+v releases %+v", h.server.rejects, h.server.releases)
	}
	h.assertRuntimeEmpty()
}

func TestShutdownReleasesTheJob(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.runner.RunChecks(context.Background())
	h.signer.block = make(chan struct{})
	b := h.build("bld_stopJOB000000001", 46, nil)
	h.enqueue(b, 1, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := h.runner.RunOnce(ctx)
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for h.signer.signCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(h.server.releases) != 1 || h.server.releases[0].Code != "SIGNER_SHUTTING_DOWN" {
		t.Fatalf("releases: %+v rejects %+v", h.server.releases, h.server.rejects)
	}
	h.assertRuntimeEmpty()
}

func TestKeyNotAcceptedWaits(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.server.checksStatus = 403
	h.enqueue(h.build("bld_waitJOB000000001", 46, nil), 1, nil)
	if h.runOnce() || len(h.server.claimBodies) != 0 {
		t.Fatal("claimed before the key was accepted")
	}
}

func TestRegister(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	if err := h.runner.Register(context.Background()); err != nil {
		t.Fatalf("active registration: %v", err)
	}
	h.server.keyStatus = "pending_key"
	if err := h.runner.Register(context.Background()); err != nil {
		t.Fatalf("pending registration: %v", err)
	}
	h.server.keyStatus, h.server.activeKey, h.server.activeEdKey = "active", testfixture.Hex64('a'), testfixture.Hex64('b')
	if err := h.runner.Register(context.Background()); err == nil {
		t.Fatal("accepted a server whose active key is another machine's")
	}
	bad := NewHTTPClient(h.server.srv.URL, "rnm_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", nil)
	r := &Runner{Config: h.cfg, Keys: h.keys, Store: h.store, API: bad, PollInterval: time.Millisecond}
	if err := r.Register(context.Background()); err == nil {
		t.Fatal("a rejected token did not stop the signer")
	}
}

// assertOutcome 检查最后一次上报：kind 为空表示 release（暂不能签），否则是 reject 的 kind。
func assertOutcome(t *testing.T, h *harness, kind string, codes ...string) {
	t.Helper()
	h.server.mu.Lock()
	defer h.server.mu.Unlock()
	var got call
	if kind == "" {
		if len(h.server.releases) == 0 {
			t.Fatalf("no release; rejects %+v; logs:\n%s", h.server.rejects, h.logsString())
		}
		got = h.server.releases[len(h.server.releases)-1]
	} else {
		if len(h.server.rejects) == 0 {
			t.Fatalf("no reject; releases %+v completes %d; logs:\n%s", h.server.releases, len(h.server.completes), h.logsString())
		}
		got = h.server.rejects[len(h.server.rejects)-1]
		if got.Kind != kind {
			t.Fatalf("reject kind %q, want %q (%+v)", got.Kind, kind, got)
		}
	}
	for _, c := range codes {
		if got.Code == c {
			return
		}
	}
	t.Fatalf("code %q (%s), want one of %v", got.Code, got.Detail, codes)
}

func (h *harness) logsString() string { return h.logs.String() }
