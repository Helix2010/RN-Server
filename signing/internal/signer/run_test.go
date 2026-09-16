package signer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/apk/apktest"
	"github.com/Helix2010/RN-Server/signing/internal/testfixture"
	"github.com/Helix2010/RN-Server/signing/policy"
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

// 包里没有 assets/fingerprint（runtimeVersion 走 appVersion 策略）：原生指纹以出处声明为准，complete 原样上报。
func TestNativeFingerprintFromProvenance(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	b := h.build("bld_nofpJOB000000001", 46, func(s *apktest.Spec) { s.NativeFingerprint = "" })
	h.enqueue(b, 1, nil)
	h.runOnce()
	if len(h.server.completes) != 1 || h.server.completes[0].NativeFingerprint != apktest.DefaultNativeFingerprint {
		t.Fatalf("completes %+v rejects %+v", h.server.completes, h.server.rejects)
	}
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
	// 第一次：签完、传上去了，complete 一直临时失败；预留停在 signed，不能再释放
	h.server.completeFails[b.JobID] = []problem{{503, "UNAVAILABLE"}, {503, "UNAVAILABLE"}, {503, "UNAVAILABLE"}}
	h.enqueue(b, 1, nil)
	h.runOnce()
	assertOutcome(t, h, "transient", "COMPLETE_FAILED")
	first := h.reservation(b.JobID)
	if first.Status != records.StatusSigned || first.SignedSHA256 != sha(h.server.uploads[b.JobID]) {
		t.Fatalf("after a failed complete: %+v", first)
	}
	if _, err := h.store.Abandon(b.JobID, "ops", "try to release"); !errors.Is(err, records.ErrAlreadySigned) {
		t.Fatalf("released a reservation whose signed package reached the server: %v", err)
	}

	// 服务端回收后同一任务、同一输入包再次派下来：续用预留，重签出的包逐字节相同
	h.enqueue(b, 2, nil)
	h.runOnce()
	if len(h.server.completes) != 1 || h.server.completes[0].SignedSHA256 != first.SignedSHA256 {
		t.Fatalf("idempotent re-sign: completes %+v rejects %+v", h.server.completes, h.server.rejects)
	}
	if list, _ := h.store.Reservations(); len(list) != 1 || list[0].Status != records.StatusCompleted {
		t.Fatalf("re-sign: %+v", list)
	}

	// 已交付的任务又派回来（例如服务端数据回滚）：不重签
	signs := h.signer.signCount()
	h.enqueue(b, 3, nil)
	h.runOnce()
	assertOutcome(t, h, "violation", "JOB_ALREADY_COMPLETED")
	if h.signer.signCount() != signs {
		t.Fatal("re-signed a job this signing gate already delivered")
	}

	// 同一任务换了输入包：永久拒签
	changed := h.build("bld_idemJOB000000001", 46, func(s *apktest.Spec) {
		s.ExtraEntries = append(s.ExtraEntries, apktest.File{Name: "assets/other.txt", Data: []byte("x")})
	})
	h.enqueue(changed, 4, nil)
	h.runOnce()
	assertOutcome(t, h, "violation", "RESERVATION_CONFLICT")

	// 另一个任务用同一个 versionCode：不大于已签最大值
	h.enqueue(h.build("bld_idemJOB000000002", 46, nil), 1, nil)
	h.runOnce()
	assertOutcome(t, h, "violation", "VERSION_CODE_NOT_INCREASING")

	// 下一个版本照常签
	h.enqueue(h.build("bld_idemJOB000000003", 47, nil), 1, nil)
	h.runOnce()
	if len(h.server.completes) != 2 {
		t.Fatalf("next version was not signed; rejects %+v", h.server.rejects)
	}
	h.assertRuntimeEmpty()
}

// ECDSA 签名带随机数：同一输入包重签出的字节不同。以最后一次签出、最后一次上传的为准。
func TestResignWithNonDeterministicSignature(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.signer.varying = true
	b := h.build("bld_ecdsaJOB00000001", 46, nil)
	h.server.completeFails[b.JobID] = []problem{{503, "UNAVAILABLE"}, {503, "UNAVAILABLE"}, {503, "UNAVAILABLE"}}
	h.enqueue(b, 1, nil)
	h.runOnce()
	assertOutcome(t, h, "transient", "COMPLETE_FAILED")
	first := h.reservation(b.JobID).SignedSHA256
	h.enqueue(b, 2, nil)
	h.runOnce()
	if len(h.server.completes) != 1 {
		t.Fatalf("second attempt did not complete: rejects %+v\n%s", h.server.rejects, h.logs.String())
	}
	got := h.server.completes[0].SignedSHA256
	if got == first || got != sha(h.server.uploads[b.JobID]) {
		t.Fatalf("complete %s, first signature %s", got, first)
	}
	if r := h.reservation(b.JobID); r.Status != records.StatusCompleted || r.SignedSHA256 != got {
		t.Fatalf("local record: %+v", r)
	}
}

func TestTransientFailures(t *testing.T) {
	t.Run("complete retried in place", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		b := h.build("bld_tranJOB000000001", 46, nil)
		h.server.completeFails[b.JobID] = []problem{{503, "UNAVAILABLE"}, {500, "INTERNAL"}}
		h.enqueue(b, 1, nil)
		h.runOnce()
		if len(h.server.completes) != 1 || len(h.server.rejects) != 0 {
			t.Fatalf("completes %d rejects %+v", len(h.server.completes), h.server.rejects)
		}
	})
	t.Run("signed upload replaced by a later upload", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		b := h.build("bld_tranJOB000000005", 46, nil)
		h.server.completeFails[b.JobID] = []problem{{409, "SIGNED_ARTIFACT_REPLACED"}}
		h.enqueue(b, 1, nil)
		h.runOnce()
		if len(h.server.completes) != 1 || len(h.server.rejects) != 0 || h.server.uploadCount[b.JobID] != 1 {
			t.Fatalf("completes %d rejects %+v uploads %d", len(h.server.completes), h.server.rejects, h.server.uploadCount[b.JobID])
		}
	})
	t.Run("signed upload lost on the server", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		b := h.build("bld_tranJOB000000006", 46, nil)
		h.server.completeFails[b.JobID] = []problem{{409, "SIGNED_ARTIFACT_MISSING"}}
		h.enqueue(b, 1, nil)
		h.runOnce()
		if len(h.server.completes) != 1 || len(h.server.rejects) != 0 || h.server.uploadCount[b.JobID] != 2 {
			t.Fatalf("completes %d rejects %+v uploads %d", len(h.server.completes), h.server.rejects, h.server.uploadCount[b.JobID])
		}
	})
	t.Run("signed upload keeps getting lost", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		b := h.build("bld_tranJOB000000007", 46, nil)
		missing := problem{409, "SIGNED_ARTIFACT_MISSING"}
		h.server.completeFails[b.JobID] = []problem{missing, missing, missing, missing}
		h.enqueue(b, 1, nil)
		h.runOnce()
		assertOutcome(t, h, "transient", "COMPLETE_FAILED")
		if h.server.uploadCount[b.JobID] != maxUploadRounds {
			t.Fatalf("uploads %d", h.server.uploadCount[b.JobID])
		}
	})
	t.Run("complete refused for a reason that is not a mismatch", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		b := h.build("bld_tranJOB000000008", 46, nil)
		h.server.completeFails[b.JobID] = []problem{{400, "INVALID_SIGN_RESULT"}}
		h.enqueue(b, 1, nil)
		h.runOnce()
		assertOutcome(t, h, "transient", "COMPLETE_FAILED")
	})
	t.Run("server refuses the signed package", func(t *testing.T) {
		for i, code := range []string{"SIGNED_ARTIFACT_MISMATCH", "SIGN_RESULT_MISMATCH"} {
			h := newHarness(t, harnessOptions{})
			b := h.build("bld_tranJOB00000003"+string(rune('0'+i)), 46, nil)
			h.server.completeFails[b.JobID] = []problem{{422, code}}
			h.enqueue(b, 1, nil)
			h.runOnce()
			assertOutcome(t, h, "violation", "SERVER_REJECTED_SIGNED_PACKAGE")
		}
	})
	t.Run("unsigned artifact missing", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		b := h.build("bld_tranJOB000000009", 46, nil)
		h.enqueue(b, 1, nil)
		h.server.mu.Lock()
		delete(h.server.apks, b.JobID)
		h.server.mu.Unlock()
		h.runOnce()
		assertOutcome(t, h, "transient", "DOWNLOAD_FAILED")
		if list, _ := h.store.Reservations(); len(list) != 0 {
			t.Fatalf("reserved without a package: %+v", list)
		}
	})
	t.Run("apksigner fails", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		h.runner.RunChecks(context.Background()) // 先让试签成功
		h.signer.failSign = errors.New("apksigner exploded")
		b := h.build("bld_tranJOB000000004", 46, nil)
		h.enqueue(b, 1, nil)
		h.runOnce()
		assertOutcome(t, h, "transient", "APKSIGNER_FAILED")
		// 没有记下签名包：预留自动释放，这个 versionCode 不被一次失败永久占住
		if r := h.reservation(b.JobID); r.Status != records.StatusAbandoned {
			t.Fatalf("reservation after a failed apksigner: %+v", r)
		}
		h.signer.failSign = nil
		h.enqueue(h.build("bld_tranJOB000000014", 46, nil), 1, nil)
		h.runOnce()
		if len(h.server.completes) != 1 {
			t.Fatalf("versionCode 46 was not released: rejects %+v", h.server.rejects)
		}
		h.assertRuntimeEmpty()
	})
}

func TestClaimOutsideTheReadyListIsDeferred(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	// 本机声明就绪的是另一份信任根摘要（例如刚重新确认），服务端却按旧摘要派活
	h.runner.setReady([]ReadyItem{{TenantSlug: testfixture.TenantSlug, PackageName: testfixture.PackageName, CertificateSHA256: h.key.CertificateSHA256, TrustRootsDigest: testfixture.Hex64('d')}})
	h.runner.lastChecks = time.Now()
	h.enqueue(h.build("bld_readyJOB00000001", 46, nil), 1, nil)
	h.runOnce()
	assertOutcome(t, h, "", "SIGNER_NOT_READY")
	if h.signer.signCount() != 0 {
		t.Fatal("signed a job that is not in the ready list")
	}
}

// tamperingChecker 在检查通过后改掉磁盘上的包：交给 apksigner 的必须是检查过的那份字节。
type tamperingChecker struct{}

func (tamperingChecker) Check(ctx context.Context, in policy.Input, path string) (policy.Verdict, error) {
	v, err := pipeChecker{}.Check(ctx, in, path)
	f, openErr := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if openErr != nil {
		return v, openErr
	}
	_, _ = f.Write([]byte("tampered"))
	_ = f.Close()
	return v, err
}

func TestUnsignedPackageChangedAfterTheCheck(t *testing.T) {
	h := newHarness(t, harnessOptions{checker: tamperingChecker{}})
	b := h.build("bld_tampJOB000000001", 46, nil)
	h.enqueue(b, 1, nil)
	h.runOnce()
	assertOutcome(t, h, "transient", "UNSIGNED_CHANGED_BEFORE_SIGNING")
	if h.signer.signCount() != 1 { // 只有试签
		t.Fatal("signed a package that changed after the check")
	}
	if r := h.reservation(b.JobID); r.Status != records.StatusAbandoned {
		t.Fatalf("reservation: %+v", r)
	}
	h.assertRuntimeEmpty()
}

func TestMachineRevokedStopsTheSigner(t *testing.T) {
	t.Run("keystore checks", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		h.server.revoked = true
		if _, err := h.runner.RunOnce(context.Background()); !errors.Is(err, errRevoked) {
			t.Fatalf("RunOnce = %v", err)
		}
	})
	t.Run("claim", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		must(t, h.runner.RunChecks(context.Background()))
		h.runner.lastChecks = time.Now()
		h.server.revoked = true
		if _, err := h.runner.RunOnce(context.Background()); !errors.Is(err, errRevoked) {
			t.Fatalf("RunOnce = %v", err)
		}
	})
	t.Run("complete", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		b := h.build("bld_revokeJOB0000001", 46, nil)
		h.server.completeFails[b.JobID] = []problem{{401, "MACHINE_REVOKED"}}
		h.enqueue(b, 1, nil)
		if _, err := h.runner.RunOnce(context.Background()); !errors.Is(err, errRevoked) {
			t.Fatalf("RunOnce = %v", err)
		}
		if len(h.server.rejects) != 0 || len(h.server.releases) != 0 {
			t.Fatalf("reported with a revoked token: %+v %+v", h.server.rejects, h.server.releases)
		}
		if r := h.reservation(b.JobID); r.Status != records.StatusSigned {
			t.Fatalf("reservation: %+v", r)
		}
		h.assertRuntimeEmpty()
	})
	t.Run("register", func(t *testing.T) {
		h := newHarness(t, harnessOptions{})
		h.server.revoked = true
		if err := h.runner.Register(context.Background()); err == nil || !IsRevoked(err) {
			t.Fatalf("Register = %v", err)
		}
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
	if r := h.reservation(b.JobID); r.Status != records.StatusAbandoned {
		t.Fatalf("reservation after an interrupted signature: %+v", r)
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
	if r := h.reservation(b.JobID); r.Status != records.StatusAbandoned {
		t.Fatalf("reservation after shutdown: %+v", r)
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
