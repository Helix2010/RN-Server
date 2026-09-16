package records

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/trustroots"
)

const (
	pkg     = "com.anyfun.foundation"
	certA   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	certB   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	shaOne  = "1111111111111111111111111111111111111111111111111111111111111111"
	shaTwo  = "2222222222222222222222222222222222222222222222222222222222222222"
	shaSign = "3333333333333333333333333333333333333333333333333333333333333333"
)

type fixture struct {
	dir  string
	priv ed25519.PrivateKey
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, GenesisParams{MachineName: "amos-signer-a", Ed25519PrivateKey: priv, X25519PublicKeySHA256: shaOne}); err != nil {
		t.Fatal(err)
	}
	return fixture{dir: dir, priv: priv}
}

func (f fixture) open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(f.dir, f.priv)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func reservation(job string, vc int64, unsigned string) Reservation {
	return Reservation{JobID: job, SignAttempt: 1, TenantSlug: "AnyFun", PackageName: pkg, CertificateSHA256: certA, VersionCode: vc, UnsignedSHA256: unsigned}
}

func confirmation(t *testing.T) Confirmation {
	t.Helper()
	roots, err := trustroots.Roots{
		APIBaseURL: "https://api.anyfun.win", OTACertificateSHA256: shaTwo,
		BootstrapSignerAddress: "0x9269ca361b9f0427ac883e89cd5b5fe113bbad17", AppLinksHosts: []string{"api.anyfun.win"},
		Scheme: "anyfun", DistributionChannel: "direct", ApplicationID: "dex-mobile",
	}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := trustroots.Digest(roots)
	return Confirmation{TenantSlug: "AnyFun", PackageName: pkg, CertificateSHA256: certA, KeyAlias: "anyfun-release",
		KeystoreVersion: 3, TrustRoots: roots, TrustRootsDigest: digest, MinSDK: 24, TargetSDK: 35,
		FirstSignMaxVersionCode: 50, ConfirmedBy: "ops-alice"}
}

func TestInitRefusesToOverwrite(t *testing.T) {
	f := newFixture(t)
	err := Init(f.dir, GenesisParams{MachineName: "amos-signer-a", Ed25519PrivateKey: f.priv, X25519PublicKeySHA256: shaOne})
	if err == nil {
		t.Fatal("Init overwrote existing records")
	}
	trust, signed, err := Exists(f.dir)
	if err != nil || !trust || !signed {
		t.Fatalf("Exists = %v %v %v", trust, signed, err)
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	f := newFixture(t)
	s := f.open(t)
	if role, _ := s.Role(); role.Role != RoleStandby {
		t.Fatalf("default role %q, want standby", role.Role)
	}
	must(t, s.SetRole(RoleChange{Role: RolePrimary, Mode: RoleModeInitial, Operator: "ops-alice", Reason: "first primary"}))
	must(t, s.TrustBuilder(BuilderTrust{BuilderID: "mch_builder01", Ed25519PublicKeySHA256: shaOne, Name: "amos-builder", Operator: "ops-alice"}))
	must(t, s.TrustBuilder(BuilderTrust{BuilderID: "mch_builder02", Ed25519PublicKeySHA256: shaTwo, Name: "old-builder", Operator: "ops-alice"}))
	must(t, s.RevokeBuilder("mch_builder02", "ops-alice", "machine rebuilt"))
	must(t, s.Confirm(confirmation(t)))
	if _, err := s.Reserve(reservation("bld_job00001", 46, shaOne)); err != nil {
		t.Fatal(err)
	}
	must(t, s.Complete("bld_job00001", shaOne, shaSign, "rel_abcdef"))
	if _, err := s.Reserve(reservation("bld_job00002", 47, shaTwo)); err != nil {
		t.Fatal(err)
	}
	must(t, s.SetBaseline(Baseline{PackageName: pkg, CertificateSHA256: certB, MaxVersionCode: 12, Operator: "ops-alice"}))
	s.Close()

	r := f.open(t)
	role, _ := r.Role()
	if role.Role != RolePrimary || role.Mode != RoleModeInitial || role.At == "" {
		t.Fatalf("role after restart: %+v", role)
	}
	builders, _ := r.TrustedBuilders()
	if len(builders) != 1 || builders[0].BuilderID != "mch_builder01" {
		t.Fatalf("builders after restart: %+v", builders)
	}
	c, ok, _ := r.Confirmation(pkg, certA)
	if !ok || c.FirstSignMaxVersionCode != 50 || c.ConfirmedAt == "" {
		t.Fatalf("confirmation after restart: %+v %v", c, ok)
	}
	view, _ := r.SignedState(pkg, certA, "bld_job00003", shaOne)
	if !view.HasMax || view.Max != 47 || view.Existing != nil {
		t.Fatalf("view after restart: %+v", view)
	}
	view, _ = r.SignedState(pkg, certB, "bld_job00003", shaOne)
	if !view.HasMax || view.Max != 12 {
		t.Fatalf("baseline after restart: %+v", view)
	}
	list, _ := r.Reservations()
	if len(list) != 2 || list[0].Status != StatusCompleted || list[0].ReleaseID != "rel_abcdef" || list[1].Status != StatusReserved {
		t.Fatalf("reservations after restart: %+v", list)
	}
	if r.Genesis().MachineName != "amos-signer-a" {
		t.Fatal("genesis lost")
	}
}

func TestReserveRules(t *testing.T) {
	f := newFixture(t)
	s := f.open(t)
	idem, err := s.Reserve(reservation("bld_job00001", 46, shaOne))
	if err != nil || idem {
		t.Fatalf("first reserve: %v %v", idem, err)
	}
	// 同一任务、同一输入包：幂等，不写新行
	before := fileSize(t, filepath.Join(f.dir, SignedFileName))
	idem, err = s.Reserve(reservation("bld_job00001", 46, shaOne))
	if err != nil || !idem {
		t.Fatalf("idempotent reserve: %v %v", idem, err)
	}
	if fileSize(t, filepath.Join(f.dir, SignedFileName)) != before {
		t.Fatal("an idempotent reserve wrote a line")
	}
	// 幂等重签时，本任务的预留不参与"大于已签最大值"的比较
	view, _ := s.SignedState(pkg, certA, "bld_job00001", shaOne)
	if view.HasMax || view.Existing == nil || view.Existing.VersionCode != 46 {
		t.Fatalf("view for the same job: %+v", view)
	}
	for name, tc := range map[string]struct {
		r    Reservation
		want error
	}{
		"other job same versionCode":         {reservation("bld_job00002", 46, shaTwo), ErrVersionCodeTaken},
		"same job other unsigned sha":        {reservation("bld_job00001", 46, shaTwo), ErrVersionCodeTaken},
		"same job other versionCode":         {reservation("bld_job00001", 47, shaOne), ErrJobConflict},
		"lower versionCode":                  {reservation("bld_job00003", 45, shaTwo), ErrVersionCodeNotIncreasing},
		"other tenant slug same versionCode": {func() Reservation { r := reservation("bld_job00004", 46, shaTwo); r.TenantSlug = "Other"; return r }(), ErrVersionCodeTaken},
	} {
		if _, err := s.Reserve(tc.r); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	// 不同证书是另一条序列
	other := reservation("bld_job00005", 1, shaTwo)
	other.CertificateSHA256 = certB
	if _, err := s.Reserve(other); err != nil {
		t.Fatalf("other certificate: %v", err)
	}
	// 释放之后同一个 versionCode 可以给别的任务
	abandoned, err := s.Abandon("bld_job00001", "ops-alice", "never delivered")
	if err != nil || abandoned.VersionCode != 46 {
		t.Fatalf("abandon: %+v %v", abandoned, err)
	}
	if _, err := s.Reserve(reservation("bld_job00006", 46, shaTwo)); err != nil {
		t.Fatalf("reserve after abandon: %v", err)
	}
	if _, err := s.Abandon("bld_job00001", "ops-alice", "twice"); !errors.Is(err, ErrNotReserved) {
		t.Fatalf("second abandon: %v", err)
	}
	must(t, s.Complete("bld_job00006", shaTwo, shaSign, "rel_one"))
	must(t, s.Complete("bld_job00006", shaTwo, shaSign, "rel_one")) // 幂等
	if err := s.Complete("bld_job00006", shaTwo, shaOne, "rel_one"); !errors.Is(err, ErrAlreadyCompleted) {
		t.Fatalf("conflicting complete: %v", err)
	}
	if err := s.Complete("bld_job00006", shaOne, shaSign, "rel_one"); !errors.Is(err, ErrNotReserved) {
		t.Fatalf("complete with other unsigned sha: %v", err)
	}
	if _, err := s.Abandon("bld_job00006", "ops-alice", "too late"); !errors.Is(err, ErrAlreadyCompleted) {
		t.Fatalf("abandon completed: %v", err)
	}
	// 已完成的任务仍可幂等重签（服务端完成请求失败后重试）
	if idem, err := s.Reserve(reservation("bld_job00006", 46, shaTwo)); err != nil || !idem {
		t.Fatalf("re-sign completed: %v %v", idem, err)
	}
	s.Close()
	f.open(t) // 整条链仍能校验
}

func TestTamperingIsDetectedAtStartup(t *testing.T) {
	build := func(t *testing.T) fixture {
		f := newFixture(t)
		s := f.open(t)
		for i, sha := range []string{shaOne, shaTwo} {
			if _, err := s.Reserve(reservation("bld_job0000"+string(rune('1'+i)), int64(46+i), sha)); err != nil {
				t.Fatal(err)
			}
		}
		must(t, s.Complete("bld_job00001", shaOne, shaSign, "rel_one"))
		s.Close()
		return f
	}
	signedPath := func(f fixture) string { return filepath.Join(f.dir, SignedFileName) }
	lines := func(t *testing.T, path string) [][]byte {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return bytes.SplitAfter(raw, []byte("\n"))[:bytes.Count(raw, []byte("\n"))]
	}
	write := func(t *testing.T, path string, parts [][]byte) {
		if err := os.WriteFile(path, bytes.Join(parts, nil), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	cases := map[string]struct {
		mutate func(t *testing.T, f fixture)
		want   error
	}{
		"flipped digit in a middle line": {func(t *testing.T, f fixture) {
			l := lines(t, signedPath(f))
			l[2] = bytes.Replace(l[2], []byte(`"versionCode":47`), []byte(`"versionCode":48`), 1)
			write(t, signedPath(f), l)
		}, ErrCorrupt},
		"deleted middle line": {func(t *testing.T, f fixture) {
			l := lines(t, signedPath(f))
			write(t, signedPath(f), append(l[:1], l[2:]...))
		}, ErrCorrupt},
		"swapped lines": {func(t *testing.T, f fixture) {
			l := lines(t, signedPath(f))
			l[1], l[2] = l[2], l[1]
			write(t, signedPath(f), l)
		}, ErrCorrupt},
		"torn last line": {func(t *testing.T, f fixture) {
			raw, _ := os.ReadFile(signedPath(f))
			write(t, signedPath(f), [][]byte{raw[:len(raw)-7]})
		}, ErrTornTail},
		"extra whitespace": {func(t *testing.T, f fixture) {
			l := lines(t, signedPath(f))
			l[3] = bytes.Replace(l[3], []byte(`,"sig":`), []byte(`, "sig":`), 1)
			write(t, signedPath(f), l)
		}, ErrCorrupt},
		"line signed by another key": {func(t *testing.T, f fixture) {
			l := lines(t, signedPath(f))
			last := l[len(l)-1]
			raw, err := encodeLine(kindSigned, uint64(len(l)), lineHash(bytes.TrimSuffix(last, []byte("\n"))), time.Now(), typeAbandon,
				abandonRecord{JobID: "bld_job00002", PackageName: pkg, CertificateSHA256: certA, VersionCode: 47, UnsignedSHA256: shaTwo, Operator: "x", Reason: "forged"}, otherPriv)
			if err != nil {
				t.Fatal(err)
			}
			write(t, signedPath(f), append(l, append(raw, '\n')))
		}, ErrCorrupt},
		"trust file copied over signed": {func(t *testing.T, f fixture) {
			raw, _ := os.ReadFile(filepath.Join(f.dir, TrustFileName))
			write(t, signedPath(f), [][]byte{raw})
		}, ErrCorrupt},
		"missing signed file": {func(t *testing.T, f fixture) {
			if err := os.Remove(signedPath(f)); err != nil {
				t.Fatal(err)
			}
		}, ErrMissing},
		"empty signed file": {func(t *testing.T, f fixture) {
			write(t, signedPath(f), nil)
		}, ErrCorrupt},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := build(t)
			tc.mutate(t, f)
			s, err := Open(f.dir, f.priv)
			if err == nil {
				s.Close()
				t.Fatal("Open accepted tampered records")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Open = %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("records of another machine", func(t *testing.T) {
		f := build(t)
		if _, err := Open(f.dir, otherPriv); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Open with another key = %v", err)
		}
	})
	t.Run("group-readable file", func(t *testing.T) {
		f := build(t)
		if err := os.Chmod(signedPath(f), 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(f.dir, f.priv); err == nil {
			t.Fatal("accepted a group-readable record file")
		}
	})
	t.Run("world-readable state dir", func(t *testing.T) {
		f := build(t)
		if err := os.Chmod(f.dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(f.dir, f.priv); err == nil {
			t.Fatal("accepted a world-readable state directory")
		}
	})
}

// 两个进程（签名闸主进程与运维命令）共用同一份记录：一方追加的行，另一方下次读写前
// 读入并校验，链接在对方的行之后。
func TestTwoStoresShareTheFiles(t *testing.T) {
	f := newFixture(t)
	daemon := f.open(t)
	operator := f.open(t)
	must(t, operator.Confirm(confirmation(t)))
	if _, ok, err := daemon.Confirmation(pkg, certA); err != nil || !ok {
		t.Fatalf("daemon did not see the operator's confirmation: %v %v", ok, err)
	}
	if _, err := daemon.Reserve(reservation("bld_job00001", 46, shaOne)); err != nil {
		t.Fatal(err)
	}
	if _, err := operator.Abandon("bld_job00001", "ops-alice", "released by operator"); err != nil {
		t.Fatalf("operator abandon: %v", err)
	}
	if _, err := daemon.Reserve(reservation("bld_job00002", 46, shaTwo)); err != nil {
		t.Fatalf("daemon reserve after operator abandon: %v", err)
	}
	must(t, operator.SetRole(RoleChange{Role: RolePrimary, Mode: RoleModeInitial, Operator: "ops-alice", Reason: "first"}))
	if role, _ := daemon.Role(); role.Role != RolePrimary {
		t.Fatal("daemon did not pick up the role change")
	}
	daemon.Close()
	operator.Close()
	f.open(t)
}

func TestForeignImport(t *testing.T) {
	primary := newFixture(t)
	p := primary.open(t)
	for i, sha := range []string{shaOne, shaTwo, shaSign} {
		if _, err := p.Reserve(reservation("bld_job0000"+string(rune('1'+i)), int64(46+i), sha)); err != nil {
			t.Fatal(err)
		}
	}
	must(t, p.Complete("bld_job00001", shaOne, shaSign, "rel_one"))
	if _, err := p.Abandon("bld_job00003", "ops-alice", "never delivered"); err != nil {
		t.Fatal(err)
	}
	must(t, p.SetBaseline(Baseline{PackageName: pkg, CertificateSHA256: certB, MaxVersionCode: 9, Operator: "ops-alice"}))
	p.Close()
	raw, err := os.ReadFile(filepath.Join(primary.dir, SignedFileName))
	if err != nil {
		t.Fatal(err)
	}
	pinned := p.Genesis().Ed25519PublicKeySHA256

	if _, err := VerifyForeignSigned(raw, shaOne); err == nil {
		t.Fatal("accepted a file with a different pinned fingerprint")
	}
	tampered := bytes.Replace(raw, []byte(`"versionCode":47`), []byte(`"versionCode":40`), 1)
	if _, err := VerifyForeignSigned(tampered, pinned); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered foreign file: %v", err)
	}
	trustRaw, _ := os.ReadFile(filepath.Join(primary.dir, TrustFileName))
	if _, err := VerifyForeignSigned(trustRaw, pinned); err == nil {
		t.Fatal("accepted trust.jsonl as a signed.jsonl")
	}
	foreign, err := VerifyForeignSigned(raw, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if len(foreign.Reservations) != 2 || len(foreign.Baselines) != 1 || foreign.Genesis.MachineName != "amos-signer-a" {
		t.Fatalf("foreign: %+v", foreign)
	}

	standby := newFixture(t)
	s := standby.open(t)
	n, err := s.Import(pinned, foreign.Reservations, "ops-bob")
	if err != nil || n != 2 {
		t.Fatalf("Import = %d, %v", n, err)
	}
	for _, b := range foreign.Baselines {
		b.Operator = "ops-bob"
		must(t, s.SetBaseline(b))
	}
	// 再导入一次：全部跳过
	if n, err := s.Import(pinned, foreign.Reservations, "ops-bob"); err != nil || n != 0 {
		t.Fatalf("second Import = %d, %v", n, err)
	}
	view, _ := s.SignedState(pkg, certA, "bld_job00009", shaOne)
	if !view.HasMax || view.Max != 47 {
		t.Fatalf("imported max: %+v", view)
	}
	// 旧主预留但没完成的任务，新主可以幂等续签；别的任务拿不到这个 versionCode
	if idem, err := s.Reserve(reservation("bld_job00002", 47, shaTwo)); err != nil || !idem {
		t.Fatalf("resume imported reservation: %v %v", idem, err)
	}
	if _, err := s.Reserve(reservation("bld_job00010", 47, shaOne)); !errors.Is(err, ErrVersionCodeTaken) {
		t.Fatalf("taken imported versionCode: %v", err)
	}
	// 被释放的 48 没有导入，但 48 > 47，所以可以签
	if _, err := s.Reserve(reservation("bld_job00011", 48, shaOne)); err != nil {
		t.Fatalf("reserve 48: %v", err)
	}
	// 与本机冲突的导入整体拒绝，一行都不写
	conflict := []Reservation{{JobID: "bld_job00099", SignAttempt: 1, TenantSlug: "AnyFun", PackageName: pkg, CertificateSHA256: certA, VersionCode: 48, UnsignedSHA256: shaTwo, Status: StatusReserved}}
	before := fileSize(t, filepath.Join(standby.dir, SignedFileName))
	if _, err := s.Import(pinned, conflict, "ops-bob"); !errors.Is(err, ErrVersionCodeTaken) {
		t.Fatalf("conflicting import: %v", err)
	}
	if fileSize(t, filepath.Join(standby.dir, SignedFileName)) != before {
		t.Fatal("a rejected import wrote lines")
	}
	s.Close()
	standby.open(t)
}

func TestRecordValidation(t *testing.T) {
	f := newFixture(t)
	s := f.open(t)
	c := confirmation(t)
	c.TrustRootsDigest = shaOne
	if err := s.Confirm(c); err == nil {
		t.Fatal("accepted a digest that does not match the roots")
	}
	c = confirmation(t)
	c.TrustRoots.BootstrapSignerAddress = "0x9269Ca361b9F0427ac883e89cD5B5fe113BBAD17"
	if err := s.Confirm(c); err == nil {
		t.Fatal("accepted non-normalized roots")
	}
	c = confirmation(t)
	c.FirstSignMaxVersionCode = 0
	if err := s.Confirm(c); err == nil {
		t.Fatal("accepted a zero first-sign cap")
	}
	if err := s.SetRole(RoleChange{Role: RolePrimary, Mode: RoleModeImportFile, Operator: "ops", Reason: "promote"}); err == nil {
		t.Fatal("accepted an import-file promotion without the previous primary fingerprint")
	}
	if err := s.RevokeBuilder("mch_unknown01", "ops", "not there"); err == nil {
		t.Fatal("revoked an unknown builder")
	}
	if err := s.TrustBuilder(BuilderTrust{BuilderID: "mch_b01\n", Ed25519PublicKeySHA256: shaOne, Name: "b", Operator: "ops"}); err == nil {
		t.Fatal("accepted a malformed builder")
	}
	if _, err := s.Abandon("bld_job00001", "ops", "\x1b[2Jreason"); err == nil {
		t.Fatal("accepted a control character in the reason")
	}
	if err := s.Complete("bld_job00001", shaOne, shaSign, "rel_x"); !errors.Is(err, ErrNotReserved) {
		t.Fatalf("complete without reservation: %v", err)
	}
	if _, err := s.Reserve(Reservation{JobID: "bld_job00001", TenantSlug: "AnyFun", PackageName: pkg, CertificateSHA256: certA, VersionCode: MaxVersionCode + 1, UnsignedSHA256: shaOne}); err == nil {
		t.Fatal("accepted a versionCode above the Android maximum")
	}
	// 所有被拒的写入都没有留下行
	s.Close()
	raw, _ := os.ReadFile(filepath.Join(f.dir, TrustFileName))
	if strings.Count(string(raw), "\n") != 1 {
		t.Fatalf("rejected writes left lines in trust.jsonl:\n%s", raw)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}
