package records

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	shaPeerX  = "4444444444444444444444444444444444444444444444444444444444444444"
	shaPeerEd = "5555555555555555555555555555555555555555555555555555555555555555"
	shaRecov  = "6666666666666666666666666666666666666666666666666666666666666666"
	shaRecov2 = "7777777777777777777777777777777777777777777777777777777777777777"
)

func peer() PeerTrust {
	return PeerTrust{Name: "amos-signer-b", X25519PublicKeySHA256: shaPeerX, Ed25519PublicKeySHA256: shaPeerEd, Mode: TrustModeOperator, Operator: "ops-alice"}
}

func TestPeerTrustLifecycle(t *testing.T) {
	f := newFixture(t)
	s := f.open(t)
	must(t, s.TrustPeer(peer()))
	g := s.Genesis()
	for name, p := range map[string]PeerTrust{
		"own name":        {Name: g.MachineName, X25519PublicKeySHA256: shaTwo, Ed25519PublicKeySHA256: shaSign, Mode: TrustModeOperator, Operator: "ops"},
		"own ed25519":     {Name: "other-signer", X25519PublicKeySHA256: shaTwo, Ed25519PublicKeySHA256: g.Ed25519PublicKeySHA256, Mode: TrustModeOperator, Operator: "ops"},
		"own x25519":      {Name: "other-signer", X25519PublicKeySHA256: g.X25519PublicKeySHA256, Ed25519PublicKeySHA256: shaSign, Mode: TrustModeOperator, Operator: "ops"},
		"same keys":       {Name: "other-signer", X25519PublicKeySHA256: shaPeerX, Ed25519PublicKeySHA256: shaSign, Mode: TrustModeOperator, Operator: "ops"},
		"bad mode":        {Name: "other-signer", X25519PublicKeySHA256: shaTwo, Ed25519PublicKeySHA256: shaSign, Mode: "server", Operator: "ops"},
		"bad fingerprint": {Name: "other-signer", X25519PublicKeySHA256: strings.ToUpper(certA), Ed25519PublicKeySHA256: shaSign, Mode: TrustModeOperator, Operator: "ops"},
		"bad operator":    {Name: "other-signer", X25519PublicKeySHA256: shaTwo, Ed25519PublicKeySHA256: shaSign, Mode: TrustModeOperator, Operator: "auto:x"},
	} {
		if err := s.TrustPeer(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// 同名重新信任（机器重装换了密钥）取代旧的
	replaced := peer()
	replaced.X25519PublicKeySHA256, replaced.Ed25519PublicKeySHA256, replaced.Mode = shaTwo, shaSign, TrustModeEnrollFirstTrust
	must(t, s.TrustPeer(replaced))
	s.Close()
	s = f.open(t)
	peers, err := s.TrustedPeers()
	if err != nil || len(peers) != 1 || peers[0].X25519PublicKeySHA256 != shaTwo || peers[0].Mode != TrustModeEnrollFirstTrust || peers[0].At == "" {
		t.Fatalf("peers after restart: %+v %v", peers, err)
	}
	if err := s.RevokePeer("amos-signer-c", "ops", "never trusted"); err == nil {
		t.Fatal("revoked an untrusted peer")
	}
	if err := s.RevokePeer("amos-signer-b", "ops", "x"); err == nil {
		t.Fatal("accepted a too short reason")
	}
	must(t, s.RevokePeer("amos-signer-b", "ops", "machine rebuilt"))
	s.Close()
	if peers, _ := f.open(t).TrustedPeers(); len(peers) != 0 {
		t.Fatalf("revoked peer survived a restart: %+v", peers)
	}
}

func TestRecoveryTrustLifecycle(t *testing.T) {
	f := newFixture(t)
	s := f.open(t)
	must(t, s.TrustRecovery(RecoveryTrust{Name: "platform-recovery", X25519PublicKeySHA256: shaRecov, Mode: TrustModeEnroll, Operator: EnrollOperator}))
	must(t, s.TrustRecovery(RecoveryTrust{Name: "platform-recovery-2", X25519PublicKeySHA256: shaRecov2, Mode: TrustModeOperator, Operator: "ops-bob", Note: "rotation 2027"}))
	if err := s.TrustRecovery(RecoveryTrust{Name: "x", X25519PublicKeySHA256: shaRecov, Mode: TrustModeOperator, Operator: "ops"}); err == nil {
		t.Fatal("accepted a malformed name")
	}
	if err := s.TrustRecovery(RecoveryTrust{Name: "platform-recovery", X25519PublicKeySHA256: shaRecov, Mode: TrustModeEnrollFirstTrust, Operator: "ops"}); err == nil {
		t.Fatal("accepted the peer-only first-trust mode for a recovery key")
	}
	must(t, s.RevokeRecovery(shaRecov, "ops-bob", "replaced by recovery 2"))
	if err := s.RevokeRecovery(shaRecov, "ops-bob", "again"); err == nil {
		t.Fatal("revoked an untrusted recovery key")
	}
	s.Close()
	keys, err := f.open(t).TrustedRecoveryKeys()
	if err != nil || len(keys) != 1 || keys[0].X25519PublicKeySHA256 != shaRecov2 || keys[0].Note != "rotation 2027" {
		t.Fatalf("recovery keys after restart: %+v %v", keys, err)
	}
}

func autoConfirmation(t *testing.T, cert, mode, request string) Confirmation {
	c := confirmation(t)
	c.CertificateSHA256, c.Mode, c.GenerationRequestID = cert, mode, request
	c.GeneratorName, c.GeneratorEd25519SHA256 = "amos-signer-a", shaSign
	c.ConfirmedBy = AutoConfirmedBy(mode, c.GeneratorName)
	return c
}

func TestAutoConfirmation(t *testing.T) {
	f := newFixture(t)
	s := f.open(t)
	first := autoConfirmation(t, certA, ConfirmModeFirstGeneration, "kgr_request0001")
	if first.ConfirmedBy != "auto:first-generation" {
		t.Fatalf("confirmedBy %q", first.ConfirmedBy)
	}
	// 决定时有确认、写入时没了
	if err := s.ConfirmAuto(first, &first); !errors.Is(err, ErrConfirmationChanged) {
		t.Fatalf("expected previous missing: %v", err)
	}
	must(t, s.ConfirmAuto(first, nil))
	must(t, s.ConfirmAuto(first, nil)) // 幂等
	trustLines := fileSize(t, filepath.Join(f.dir, TrustFileName))

	regenerated := autoConfirmation(t, certB, ConfirmModeRegenerated, "kgr_request0002")
	// 决定时没有确认、写入时已经有了
	if err := s.ConfirmAuto(regenerated, nil); !errors.Is(err, ErrConfirmationChanged) {
		t.Fatalf("expected none but one exists: %v", err)
	}
	stale := first
	stale.TrustRootsDigest = shaTwo
	if err := s.ConfirmAuto(regenerated, &stale); !errors.Is(err, ErrConfirmationChanged) {
		t.Fatalf("expected previous with another digest: %v", err)
	}
	if fileSize(t, filepath.Join(f.dir, TrustFileName)) != trustLines {
		t.Fatal("a refused automatic confirmation wrote a record")
	}
	must(t, s.ConfirmAuto(regenerated, &first))
	if seen, _ := s.CertificateSeen(pkg, certA); !seen {
		t.Fatal("the superseded certificate is not remembered")
	}
	// 被取代的证书不能自动确认回去（重放旧的生成）
	back := autoConfirmation(t, certA, ConfirmModePeerGenerated, "kgr_request0003")
	if err := s.ConfirmAuto(back, &regenerated); !errors.Is(err, ErrCertificateSeen) {
		t.Fatalf("switching back to a superseded certificate: %v", err)
	}
	// 运维 confirm 可以
	manual := confirmation(t)
	must(t, s.Confirm(manual))

	s.Close()
	s = f.open(t)
	c, ok, err := s.ActiveConfirmation(pkg)
	if err != nil || !ok || c.Mode != "" || c.ConfirmedBy != "ops-alice" {
		t.Fatalf("active confirmation after restart: %+v %v", c, err)
	}
	if seen, _ := s.CertificateSeen(pkg, certB); !seen {
		t.Fatal("certificate history did not survive a restart")
	}
	if seen, _ := s.CertificateSeen("com.other.app", certB); seen {
		t.Fatal("certificate history leaked across packages")
	}
}

func TestConfirmationModeValidation(t *testing.T) {
	f := newFixture(t)
	s := f.open(t)
	cases := map[string]func(*Confirmation){
		"operator with request id": func(c *Confirmation) { c.GenerationRequestID = "kgr_x" },
		"operator named auto":      func(c *Confirmation) { c.ConfirmedBy = "auto:first-generation" },
		"unknown mode":             func(c *Confirmation) { c.Mode = "server"; c.ConfirmedBy = "auto:server" },
		"auto with operator name": func(c *Confirmation) {
			*c = autoConfirmation(t, certA, ConfirmModeRegenerated, "kgr_x")
			c.ConfirmedBy = "ops"
		},
		"auto without request":    func(c *Confirmation) { *c = autoConfirmation(t, certA, ConfirmModeRegenerated, "") },
		"auto request with slash": func(c *Confirmation) { *c = autoConfirmation(t, certA, ConfirmModeRegenerated, "kgr/x") },
		"auto without generator": func(c *Confirmation) {
			*c = autoConfirmation(t, certA, ConfirmModeRegenerated, "kgr_x")
			c.GeneratorEd25519SHA256 = ""
		},
		"peer confirmedBy mismatch": func(c *Confirmation) {
			*c = autoConfirmation(t, certA, ConfirmModePeerGenerated, "kgr_x")
			c.ConfirmedBy = "auto:peer-generated:other"
		},
	}
	for name, mutate := range cases {
		c := confirmation(t)
		mutate(&c)
		if err := s.Confirm(c); err == nil {
			t.Errorf("%s: Confirm accepted", name)
		}
		if c.Mode != "" {
			if err := s.ConfirmAuto(c, nil); err == nil {
				t.Errorf("%s: ConfirmAuto accepted", name)
			}
		}
	}
	if err := s.ConfirmAuto(confirmation(t), nil); err == nil {
		t.Fatal("ConfirmAuto accepted an operator confirmation")
	}
	peerConf := autoConfirmation(t, certA, ConfirmModePeerGenerated, "kgr_x")
	if peerConf.ConfirmedBy != "auto:peer-generated:amos-signer-a" {
		t.Fatalf("peer confirmedBy %q", peerConf.ConfirmedBy)
	}
	must(t, s.ConfirmAuto(peerConf, nil))
	// 运维确认的 JSON 与旧版本同形：没有新增字段
	raw, _ := json.Marshal(confirmation(t))
	for _, field := range []string{"mode", "generationRequestId", "generatorName", "generatorEd25519Sha256"} {
		if strings.Contains(string(raw), `"`+field+`"`) {
			t.Fatalf("an operator confirmation serializes %s: %s", field, raw)
		}
	}
}

func TestEnrollRoleAndPackageMax(t *testing.T) {
	f := newFixture(t)
	s := f.open(t)
	if err := s.SetRole(RoleChange{Role: RolePrimary, Mode: RoleModeEnroll, PreviousPrimaryEd25519SHA256: shaTwo, Operator: EnrollOperator, Reason: "enrolled"}); err == nil {
		t.Fatal("an enrollment role named a previous primary")
	}
	must(t, s.SetRole(RoleChange{Role: RoleStandby, Mode: RoleModeEnroll, Operator: EnrollOperator, Reason: "enrolled as standby"}))
	if r, _ := s.Role(); r.Role != RoleStandby || r.Mode != RoleModeEnroll {
		t.Fatalf("role %+v", r)
	}
	if _, ok, err := s.PackageMaxVersionCode(pkg); ok || err != nil {
		t.Fatal("a fresh record has a package maximum")
	}
	_, err := s.reserveT(reservation("bld_job00000001", 40, shaOne))
	must(t, err)
	other := reservation("bld_job00000002", 70, shaTwo)
	other.CertificateSHA256 = certB
	_, err = s.reserveT(other)
	must(t, err)
	must(t, s.SetBaseline(Baseline{PackageName: "com.other.app", CertificateSHA256: certA, MaxVersionCode: 900, Operator: "ops"}))
	if max, ok, _ := s.PackageMaxVersionCode(pkg); !ok || max != 70 {
		t.Fatalf("package max %d %v", max, ok)
	}
	_, err = s.Abandon("bld_job00000002", "ops", "released for the test")
	must(t, err)
	if max, ok, _ := s.PackageMaxVersionCode(pkg); !ok || max != 40 {
		t.Fatalf("package max after abandon %d %v", max, ok)
	}
	must(t, s.SetBaseline(Baseline{PackageName: pkg, CertificateSHA256: certB, MaxVersionCode: 55, Operator: "ops"}))
	if max, ok, _ := s.PackageMaxVersionCode(pkg); !ok || max != 55 {
		t.Fatalf("package max with a baseline %d %v", max, ok)
	}
}

// testdata/legacy-2026-09-16 是上线前（手工流程）的代码写出的本机记录：genesis、role(initial)、
// builder、builder-revoke、tenant、reserve/signed/complete、reserve/abandon。新代码必须能读，
// 并能在它后面追加新的记录类型。
func TestLegacyRecordsStayReadable(t *testing.T) {
	dir := copyLegacyState(t)
	seed, err := os.ReadFile(filepath.Join(dir, "ed25519.key"))
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	s, err := Open(dir, priv)
	if err != nil {
		t.Fatalf("Open legacy records: %v", err)
	}
	role, _ := s.Role()
	builders, _ := s.TrustedBuilders()
	confs, _ := s.Confirmations()
	reservations, _ := s.Reservations()
	if role.Role != RolePrimary || role.Mode != RoleModeInitial || len(builders) != 1 || builders[0].BuilderID != "mch_builderLEGACY0001" ||
		len(confs) != 1 || confs[0].Mode != "" || confs[0].ConfirmedBy != "ops-alice" || len(reservations) != 2 ||
		reservations[0].Status != StatusCompleted || reservations[1].Status != StatusAbandoned {
		t.Fatalf("legacy state: role %+v builders %+v confirmations %+v reservations %+v", role, builders, confs, reservations)
	}
	old := confs[0]
	if seen, _ := s.CertificateSeen(old.PackageName, old.CertificateSHA256); !seen {
		t.Fatal("legacy confirmation is not in the certificate history")
	}
	// 在旧记录后面追加新类型
	must(t, s.TrustPeer(peer()))
	must(t, s.TrustRecovery(RecoveryTrust{Name: "platform-recovery", X25519PublicKeySHA256: shaRecov, Mode: TrustModeOperator, Operator: "ops-alice"}))
	next := old
	next.CertificateSHA256, next.Mode, next.GenerationRequestID = certB, ConfirmModeRegenerated, "kgr_request0001"
	next.GeneratorName, next.GeneratorEd25519SHA256 = s.Genesis().MachineName, s.Genesis().Ed25519PublicKeySHA256
	next.ConfirmedBy = AutoConfirmedBy(next.Mode, next.GeneratorName)
	must(t, s.ConfirmAuto(next, &old))
	if max, ok, _ := s.PackageMaxVersionCode(old.PackageName); !ok || max != 101 {
		t.Fatalf("legacy package max %d %v", max, ok)
	}
	s.Close()
	s, err = Open(dir, priv)
	if err != nil {
		t.Fatalf("reopen after appending new record types: %v", err)
	}
	defer s.Close()
	c, ok, _ := s.ActiveConfirmation(old.PackageName)
	peers, _ := s.TrustedPeers()
	keys, _ := s.TrustedRecoveryKeys()
	if !ok || c.CertificateSHA256 != certB || c.ConfirmedBy != "auto:regenerated" || len(peers) != 1 || len(keys) != 1 {
		t.Fatalf("after reopen: %+v peers %+v recovery %+v", c, peers, keys)
	}
}

// copyLegacyState 把夹具拷进 0700 目录（git 不保存 0600 权限）。
func copyLegacyState(t *testing.T) string {
	t.Helper()
	src := filepath.Join("testdata", "legacy-2026-09-16")
	dir := t.TempDir()
	must(t, os.Chmod(dir, 0o700))
	for _, name := range []string{TrustFileName, SignedFileName, "ed25519.key"} {
		raw, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatal(err)
		}
		must(t, os.WriteFile(filepath.Join(dir, name), raw, 0o600))
	}
	return dir
}
