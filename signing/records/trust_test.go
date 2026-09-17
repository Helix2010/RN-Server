package records

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		"own name":    {Name: g.MachineName, X25519PublicKeySHA256: shaTwo, Ed25519PublicKeySHA256: shaSign, Mode: TrustModeOperator, Operator: "ops"},
		"own ed25519": {Name: "other-signer", X25519PublicKeySHA256: shaTwo, Ed25519PublicKeySHA256: g.Ed25519PublicKeySHA256, Mode: TrustModeOperator, Operator: "ops"},
		"own x25519":  {Name: "other-signer", X25519PublicKeySHA256: g.X25519PublicKeySHA256, Ed25519PublicKeySHA256: shaSign, Mode: TrustModeOperator, Operator: "ops"},
		"same keys":   {Name: "other-signer", X25519PublicKeySHA256: shaPeerX, Ed25519PublicKeySHA256: shaSign, Mode: TrustModeOperator, Operator: "ops"},
		"bad mode":    {Name: "other-signer", X25519PublicKeySHA256: shaTwo, Ed25519PublicKeySHA256: shaSign, Mode: "server", Operator: "ops"},
		// 评审 P1-2：enroll 不再首次信任服务端给的主，这个来源不再合法
		"enroll first trust": {Name: "other-signer", X25519PublicKeySHA256: shaTwo, Ed25519PublicKeySHA256: shaSign, Mode: "enroll-first-trust", Operator: EnrollOperator},
		"bad fingerprint":    {Name: "other-signer", X25519PublicKeySHA256: strings.ToUpper(certA), Ed25519PublicKeySHA256: shaSign, Mode: TrustModeOperator, Operator: "ops"},
		"bad operator":       {Name: "other-signer", X25519PublicKeySHA256: shaTwo, Ed25519PublicKeySHA256: shaSign, Mode: TrustModeOperator, Operator: "auto:x"},
	} {
		if err := s.TrustPeer(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// 同名重新信任（机器重装换了密钥）取代旧的
	replaced := peer()
	replaced.X25519PublicKeySHA256, replaced.Ed25519PublicKeySHA256, replaced.Note = shaTwo, shaSign, "reinstalled"
	must(t, s.TrustPeer(replaced))
	s.Close()
	s = f.open(t)
	peers, err := s.TrustedPeers()
	if err != nil || len(peers) != 1 || peers[0].X25519PublicKeySHA256 != shaTwo || peers[0].Note != "reinstalled" || peers[0].At == "" {
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
	if err := s.TrustRecovery(RecoveryTrust{Name: "platform-recovery", X25519PublicKeySHA256: shaRecov, Mode: "enroll-first-trust", Operator: "ops"}); err == nil {
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
	// 调用方传的是计划时从本机记录读到的那一份（带确认时间），不是自己拼的
	if err := s.ConfirmAuto(regenerated, &first); !errors.Is(err, ErrConfirmationChanged) {
		t.Fatalf("expected previous without the recorded fields: %v", err)
	}
	planned, _, _ := s.ActiveConfirmation(pkg)
	must(t, s.ConfirmAuto(regenerated, &planned))
	if seen, _ := s.CertificateSeen(pkg, certA); !seen {
		t.Fatal("the superseded certificate is not remembered")
	}
	// 被取代的证书不能自动确认回去（重放旧的生成）
	back := autoConfirmation(t, certA, ConfirmModePeerGenerated, "kgr_request0003")
	current, _, _ := s.ActiveConfirmation(pkg)
	if err := s.ConfirmAuto(back, &current); !errors.Is(err, ErrCertificateSeen) {
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
	// 评审 P1-1：注册只能写本机备；主只由本机 promote 产生
	if err := s.SetRole(RoleChange{Role: RolePrimary, Mode: RoleModeEnroll, Operator: EnrollOperator, Reason: "enrolled"}); err == nil {
		t.Fatal("an enrollment role record made this machine primary")
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

// 评审 P2-7：自动确认在记录锁里复核的不只是租户、证书、摘要。计划时读到的 SDK 下限、首签上限等任何一项
// 在这期间被运维 confirm 改过（哪怕只收紧了一项），都要 ErrConfirmationChanged，下一轮按新值重算，
// 不能拿旧计划把运维刚收紧的值写回去。
func TestAutoConfirmationRechecksEveryPlannedParameter(t *testing.T) {
	f := newFixture(t)
	s := f.open(t)
	manual := confirmation(t)
	must(t, s.Confirm(manual))
	planned, ok, err := s.ActiveConfirmation(pkg)
	if err != nil || !ok {
		t.Fatalf("active confirmation: %v %v", ok, err)
	}
	next := autoConfirmation(t, certB, ConfirmModeRegenerated, "kgr_request0009")
	for name, mutate := range map[string]func(*Confirmation){
		"minSdk raised":          func(c *Confirmation) { c.MinSDK = 26 },
		"targetSdk raised":       func(c *Confirmation) { c.TargetSDK = 34 },
		"first-sign cap lowered": func(c *Confirmation) { c.FirstSignMaxVersionCode = 10 },
		"key alias":              func(c *Confirmation) { c.KeyAlias = "anyfun-release-2" },
		"re-confirmed unchanged": func(c *Confirmation) {},
	} {
		t.Run(name, func(t *testing.T) {
			g := newFixture(t)
			s := g.open(t)
			must(t, s.Confirm(manual))
			planned, _, _ := s.ActiveConfirmation(pkg)
			// 运维在自动确认计划之后又 confirm 了一次
			concurrent := manual
			mutate(&concurrent)
			s.now = func() time.Time { return time.Now().Add(time.Second) }
			must(t, s.Confirm(concurrent))
			before := fileSize(t, filepath.Join(g.dir, TrustFileName))
			if err := s.ConfirmAuto(next, &planned); !errors.Is(err, ErrConfirmationChanged) {
				t.Fatalf("ConfirmAuto over a changed confirmation: %v", err)
			}
			if fileSize(t, filepath.Join(g.dir, TrustFileName)) != before {
				t.Fatal("a refused automatic confirmation wrote a record")
			}
			if c, _, _ := s.ActiveConfirmation(pkg); c.CertificateSHA256 != certA || c.MinSDK != concurrent.MinSDK || c.FirstSignMaxVersionCode != concurrent.FirstSignMaxVersionCode {
				t.Fatalf("the operator's confirmation was replaced: %+v", c)
			}
		})
	}
	// 没有并发写：同一份计划照常写入
	must(t, s.ConfirmAuto(next, &planned))
}

// 评审 P1-3：提升为主时，本机受信签名闸里用旧主 Ed25519 的那台在同一次写入里撤销；旧主被攻破、服务端把它
// 报成 active，新密钥也不再加密给它、它签的生成也不再被接受。
func TestPromoteRevokesThePreviousPrimary(t *testing.T) {
	f := newFixture(t)
	s := f.open(t)
	old := peer()
	other := PeerTrust{Name: "amos-signer-c", X25519PublicKeySHA256: shaRecov, Ed25519PublicKeySHA256: shaRecov2, Mode: TrustModeOperator, Operator: "ops"}
	must(t, s.TrustPeer(old))
	must(t, s.TrustPeer(other))
	if _, err := s.Promote(RoleChange{Role: RoleStandby, Mode: RoleModeManual, Operator: "ops", Reason: "not a promotion"}); err == nil {
		t.Fatal("Promote wrote a standby role")
	}
	before := fileSize(t, filepath.Join(f.dir, TrustFileName))
	if _, err := s.Promote(RoleChange{Role: RolePrimary, Mode: RoleModeImportFile, Operator: "ops", Reason: "x"}); err == nil {
		t.Fatal("Promote accepted an invalid role change")
	}
	if fileSize(t, filepath.Join(f.dir, TrustFileName)) != before {
		t.Fatal("a refused promotion wrote a record")
	}
	revoked, err := s.Promote(RoleChange{Role: RolePrimary, Mode: RoleModeImportFile, PreviousPrimaryEd25519SHA256: old.Ed25519PublicKeySHA256, Operator: "ops-carol", Reason: "old primary disk failed"})
	if err != nil || len(revoked) != 1 || revoked[0] != old.Name {
		t.Fatalf("Promote: %v revoked %v", err, revoked)
	}
	s.Close()
	s = f.open(t)
	role, _ := s.Role()
	peers, _ := s.TrustedPeers()
	if role.Role != RolePrimary || role.PreviousPrimaryEd25519SHA256 != old.Ed25519PublicKeySHA256 || len(peers) != 1 || peers[0].Name != other.Name {
		t.Fatalf("after restart: role %+v peers %+v", role, peers)
	}
	raw, _ := os.ReadFile(filepath.Join(f.dir, TrustFileName))
	if !strings.Contains(string(raw), `"type":"peer-revoke"`) || !strings.Contains(string(raw), "被本机提升取代") {
		t.Fatalf("no peer-revoke record naming the promotion:\n%s", raw)
	}

	// 旧主不在本机信任里、或者没给旧主指纹：只写角色
	g := newFixture(t)
	s2 := g.open(t)
	must(t, s2.TrustPeer(other))
	if revoked, err := s2.Promote(RoleChange{Role: RolePrimary, Mode: RoleModeManual, PreviousPrimaryEd25519SHA256: shaSign, Operator: "ops", Reason: "old primary lost"}); err != nil || len(revoked) != 0 {
		t.Fatalf("Promote without a trusted old primary: %v %v", revoked, err)
	}
	if peers, _ := s2.TrustedPeers(); len(peers) != 1 {
		t.Fatalf("revoked a signing gate that was not the old primary: %+v", peers)
	}
}

// 评审 P2-1：首次信任按租户判断。租户在本机确认过（任何包名，含已被取代的确认）就不再首次信任。
func TestTenantConfirmedPackage(t *testing.T) {
	f := newFixture(t)
	s := f.open(t)
	if _, ok, err := s.TenantConfirmedPackage("AnyFun"); ok || err != nil {
		t.Fatalf("a fresh record knows the tenant: %v %v", ok, err)
	}
	must(t, s.Confirm(confirmation(t)))
	// 这个包名后来确认给了另一个租户：AnyFun 仍算确认过
	moved := confirmation(t)
	moved.TenantSlug, moved.CertificateSHA256 = "Predict", certB
	must(t, s.Confirm(moved))
	s.Close()
	s = f.open(t)
	for tenant, want := range map[string]string{"AnyFun": pkg, "Predict": pkg} {
		if got, ok, err := s.TenantConfirmedPackage(tenant); !ok || err != nil || got != want {
			t.Errorf("%s: %q %v %v", tenant, got, ok, err)
		}
	}
	if _, ok, _ := s.TenantConfirmedPackage("Other"); ok {
		t.Fatal("an unknown tenant is reported as confirmed")
	}
}

// 修复之前的 enroll 写过「注册即为主」与「首次信任服务端给的主」（只在开发环境出现过）：这两种记录现在
// 校验不过，签名闸拒绝启动，按新机器重装，不会带着服务端定下的主或信任继续运行。
func TestPreFixEnrollRecordsAreRefused(t *testing.T) {
	for name, rec := range map[string]struct {
		typ  string
		data any
	}{
		"enrolled as primary": {typeRole, RoleChange{Role: RolePrimary, Mode: RoleModeEnroll, Operator: EnrollOperator, Reason: "initial role from the server at enrollment"}},
		"first-trusted primary": {typePeer, PeerTrust{Name: "amos-signer-b", X25519PublicKeySHA256: shaPeerX, Ed25519PublicKeySHA256: shaPeerEd,
			Mode: "enroll-first-trust", Operator: EnrollOperator, Note: "first trust: the server's primary signing gate at enrollment"}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			s := f.open(t)
			raw, err := encodeLine(kindTrust, s.trust.v.seq, s.trust.v.tail, time.Now(), rec.typ, rec.data, f.priv)
			must(t, err)
			s.Close()
			file, err := os.OpenFile(filepath.Join(f.dir, TrustFileName), os.O_WRONLY|os.O_APPEND, 0)
			must(t, err)
			_, err = file.Write(append(raw, '\n'))
			must(t, err)
			must(t, file.Close())
			if _, err := Open(f.dir, f.priv); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Open over a pre-fix enroll record: %v", err)
			}
		})
	}
}

// 重新封装（ConfirmModePeerResealed）：新备按受信签名闸重新封装的同一张证书首次信任。确认人带封装者的名字；请求 id
// 必须是 rsl_ 开头的重新封装 id（生成请求 id 不能冒充）；回放之后仍然读得出来。
func TestPeerResealedConfirmation(t *testing.T) {
	f := newFixture(t)
	s := f.open(t)
	resealed := autoConfirmation(t, certA, ConfirmModePeerResealed, "rsl_fixtureRESEAL000000001")
	if resealed.ConfirmedBy != "auto:peer-resealed:amos-signer-a" {
		t.Fatalf("confirmedBy %q", resealed.ConfirmedBy)
	}
	for name, mutate := range map[string]func(*Confirmation){
		"generation request id":  func(c *Confirmation) { c.GenerationRequestID = "kgr_request0001" },
		"short reseal id":        func(c *Confirmation) { c.GenerationRequestID = "rsl_short" },
		"generated confirmedBy":  func(c *Confirmation) { c.ConfirmedBy = "auto:peer-generated:amos-signer-a" },
		"another resealer named": func(c *Confirmation) { c.ConfirmedBy = "auto:peer-resealed:other" },
	} {
		bad := resealed
		mutate(&bad)
		if err := s.ConfirmAuto(bad, nil); err == nil {
			t.Errorf("%s: ConfirmAuto accepted", name)
		}
	}
	must(t, s.ConfirmAuto(resealed, nil))
	s.Close()
	s = f.open(t)
	c, ok, err := s.ActiveConfirmation(pkg)
	if err != nil || !ok || c.Mode != ConfirmModePeerResealed || c.GenerationRequestID != "rsl_fixtureRESEAL000000001" || c.GeneratorName != "amos-signer-a" {
		t.Fatalf("after restart: %+v %v", c, err)
	}
}
