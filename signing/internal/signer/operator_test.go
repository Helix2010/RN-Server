package signer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/signing/internal/testfixture"
	"github.com/Helix2010/RN-Server/signing/pins"
	"github.com/Helix2010/RN-Server/signing/records"
	"github.com/Helix2010/RN-Server/signing/trustroots"
)

// fakeTerm 是脚本化的终端：输入经过与真终端相同的 readLine 清洗。
type fakeTerm struct {
	r   *bufio.Reader
	out bytes.Buffer
}

func newTerm(lines ...string) *fakeTerm {
	return &fakeTerm{r: bufio.NewReader(strings.NewReader(strings.Join(lines, "\n") + "\n"))}
}

func (f *fakeTerm) Write(p []byte) (int, error) { return f.out.Write(p) }

func (f *fakeTerm) ReadLine(prompt string) (string, error) {
	f.out.WriteString(prompt)
	return readLine(f.r)
}

func (h *harness) operatorEnv(term Terminal) OperatorEnv {
	return OperatorEnv{Config: h.cfg, Keys: h.keys, Store: h.store, API: NewHTTPClient(h.server.srv.URL, testToken, nil), Term: term}
}

func colonUpper(hex string) string {
	var parts []string
	for i := 0; i < len(hex); i += 2 {
		parts = append(parts, strings.ToUpper(hex[i:i+2]))
	}
	return strings.Join(parts, ":")
}

func (h *harness) confirmInputs() []string {
	return []string{
		"ops-alice",
		colonUpper(h.key.CertificateSHA256), // keytool 的写法也接受
		"https://api.anyfun.win",
		h.roots.OTACertificateSHA256,
		"0x9269Ca361b9F0427ac883e89cD5B5fe113BBAD17",
		"api.anyfun.win",
		"anyfun",
		"direct",
		"dex-mobile",
		"24",
		"35",
		"50",
		testfixture.TenantSlug,
	}
}

func TestConfirmWritesOperatorValuesAndReports(t *testing.T) {
	h := newHarness(t, harnessOptions{noConfirm: true})
	term := newTerm(h.confirmInputs()...)
	if err := Confirm(context.Background(), h.operatorEnv(term), testfixture.TenantSlug); err != nil {
		t.Fatalf("Confirm: %v\n%s", err, term.out.String())
	}
	c, ok, err := h.store.Confirmation(testfixture.PackageName, h.key.CertificateSHA256)
	if err != nil || !ok {
		t.Fatalf("no confirmation written: %v", err)
	}
	if c.TenantSlug != "AnyFun" || c.KeyAlias != testAlias || c.MinSDK != 24 || c.TargetSDK != 35 || c.FirstSignMaxVersionCode != 50 ||
		c.ConfirmedBy != "ops-alice" || c.TrustRootsDigest != h.digest || !trustroots.Equal(c.TrustRoots, h.roots) || c.KeystoreVersion != 3 {
		t.Fatalf("confirmation: %+v", c)
	}
	if roles := h.server.localRoles; len(roles) == 0 || roles[len(roles)-1] != "primary" {
		t.Fatalf("confirm reported local roles %v", roles)
	}
	last := h.server.reports[len(h.server.reports)-1]
	if len(last) != 1 || last[0].Decrypt != "ok" || !last[0].Confirmed || *last[0].ConfirmedTrustRootsDigest != h.digest || last[0].TrialSign != "pending" {
		t.Fatalf("report: %+v", last)
	}
	// 服务端给的别名只作对照：确认里记的是密文里的别名
	if strings.Contains(term.out.String(), serverAlias) {
		t.Fatal("the server's alias was displayed as if it were trusted")
	}
}

func TestConfirmSDKFloorsAndSupersede(t *testing.T) {
	h := newHarness(t, harnessOptions{noConfirm: true})
	// minSdk 23、targetSdk 27 低于地板：各自重问，三次都不对就放弃
	inputs := h.confirmInputs()
	sdk := len(inputs) - 4
	low := append(append(append([]string{}, inputs[:sdk]...), "23", "24", "27", "28"), inputs[sdk+2:]...)
	term := newTerm(low...)
	if err := Confirm(context.Background(), h.operatorEnv(term), testfixture.TenantSlug); err != nil {
		t.Fatalf("Confirm: %v\n%s", err, term.out.String())
	}
	c, ok, _ := h.store.Confirmation(testfixture.PackageName, h.key.CertificateSHA256)
	if !ok || c.MinSDK != 24 || c.TargetSDK != 28 {
		t.Fatalf("confirmation: %+v", c)
	}
	if strings.Contains(term.out.String(), "replaces the active confirmation") {
		t.Fatal("warned about superseding on the first confirmation")
	}
	// 再确认一次：提示取代了哪一份
	term = newTerm(h.confirmInputs()...)
	if err := Confirm(context.Background(), h.operatorEnv(term), testfixture.TenantSlug); err != nil {
		t.Fatalf("second Confirm: %v", err)
	}
	if !strings.Contains(term.out.String(), "replaces the active confirmation for package "+testfixture.PackageName) || strings.Contains(term.out.String(), "certificate changes") {
		t.Fatalf("supersede warning:\n%s", term.out.String())
	}
}

func TestConfirmNeverShowsTheCertificateBeforeThePaste(t *testing.T) {
	h := newHarness(t, harnessOptions{noConfirm: true})
	inputs := h.confirmInputs()
	inputs[1] = testfixture.Hex64('d')
	term := newTerm(inputs...)
	err := Confirm(context.Background(), h.operatorEnv(term), testfixture.TenantSlug)
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("Confirm = %v", err)
	}
	if strings.Contains(term.out.String(), h.key.CertificateSHA256) {
		t.Fatal("the computed fingerprint was printed, so the operator could copy it from the screen")
	}
	if _, ok, _ := h.store.Confirmation(testfixture.PackageName, h.key.CertificateSHA256); ok {
		t.Fatal("a mismatched fingerprint still wrote a confirmation")
	}
	if len(h.server.reports) != 0 {
		t.Fatal("reported a confirmation that did not happen")
	}
}

func TestConfirmRejectsHostileServerStrings(t *testing.T) {
	const hostile = "\x1b[2J\x1b[HConfirmed OK"
	for name, mutate := range map[string]func(map[string]any){
		"package name": func(item map[string]any) { item["packageName"] = "com.anyfun" + hostile },
		"key alias":    func(item map[string]any) { item["keyAlias"] = hostile },
		"certificate":  func(item map[string]any) { item["certificateSha256"] = hostile },
		"trust roots url": func(item map[string]any) {
			r := testfixture.Roots(t)
			r.APIBaseURL = "https://api.anyfun.win" + hostile
			item["trustRoots"] = r
		},
		"trust roots host": func(item map[string]any) {
			r := testfixture.Roots(t)
			r.AppLinksHosts = []string{hostile}
			item["trustRoots"] = r
		},
		"digest mismatch":  func(item map[string]any) { item["trustRootsDigest"] = testfixture.Hex64('0') },
		"digest with junk": func(item map[string]any) { item["trustRootsDigest"] = hostile },
		"roots not normalized": func(item map[string]any) {
			r := testfixture.Roots(t)
			r.BootstrapSignerAddress = "0x9269Ca361b9F0427ac883e89cD5B5fe113BBAD17"
			item["trustRoots"] = r
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, harnessOptions{noConfirm: true})
			mutate(h.server.items[0])
			term := newTerm(h.confirmInputs()...)
			err := Confirm(context.Background(), h.operatorEnv(term), testfixture.TenantSlug)
			if err == nil {
				t.Fatal("accepted a malformed server record")
			}
			if strings.Contains(term.out.String()+err.Error(), "\x1b") || strings.Contains(err.Error(), "Confirmed OK") {
				t.Fatalf("the hostile string reached the terminal: %q", term.out.String()+err.Error())
			}
			if list, _ := h.store.Confirmations(); len(list) != 0 {
				t.Fatal("wrote a confirmation")
			}
		})
	}
}

func TestConfirmRejectsControlCharactersInOperatorInput(t *testing.T) {
	h := newHarness(t, harnessOptions{noConfirm: true})
	inputs := h.confirmInputs()
	inputs[2] = "https://api.anyfun.win\x1b[A"
	err := Confirm(context.Background(), h.operatorEnv(newTerm(inputs...)), testfixture.TenantSlug)
	if !errors.Is(err, ErrControlCharacters) {
		t.Fatalf("Confirm = %v", err)
	}
	inputs = h.confirmInputs()
	inputs[len(inputs)-1] = "anyfun" // 最后要求原样输入 slug（区分大小写）
	if err := Confirm(context.Background(), h.operatorEnv(newTerm(inputs...)), testfixture.TenantSlug); !errors.Is(err, ErrAborted) {
		t.Fatalf("wrong final slug: %v", err)
	}
	if list, _ := h.store.Confirmations(); len(list) != 0 {
		t.Fatal("wrote a confirmation")
	}
}

// 非 TTY：在读取任何配置、连接服务端之前就拒绝。
func TestOperatorCommandsRefuseWithoutATerminal(t *testing.T) {
	h := newHarness(t, harnessOptions{noConfirm: true})
	env := map[string]string{
		EnvServerURL: h.server.srv.URL, EnvMachineToken: testToken, EnvName: testMachine, EnvStateDir: h.cfg.StateDir,
	}
	getenv := func(k string) string { return env[k] }
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipeR.Close()
	defer pipeW.Close()
	for _, stdin := range []*os.File{devnull, pipeR} {
		for _, args := range [][]string{
			{"confirm", "--tenant", "AnyFun"},
			{"trust-builder", "--builder-id", "mch_builderXYZ01", "--name", "amos-builder"},
			{"trust-builder", "--revoke", "--builder-id", "mch_builderXYZ01", "--reason", "rebuilt"},
			{"trust-builder", "--builder", "amos-builder"},
			{"trust-peer", "--peer", "amos-signer-b"},
			{"trust-peer", "--revoke", "--peer", "amos-signer-b", "--reason", "rebuilt"},
			{"trust-recovery"},
			{"trust-recovery", "--revoke", "--recovery-sha256", strings.Repeat("a", 64), "--reason", "rotated"},
			{"promote", "--first"},
			{"abandon", "--job", "bld_job0000000001", "--reason", "never delivered"},
		} {
			var stdout, stderr bytes.Buffer
			if code := Main(args, stdin, &stdout, &stderr, getenv); code != 1 || !strings.Contains(stderr.String(), "interactive terminal") {
				t.Fatalf("%v: exit %d, stderr %q", args, code, stderr.String())
			}
		}
	}
	h.server.mu.Lock()
	defer h.server.mu.Unlock()
	if len(h.server.reports) != 0 {
		t.Fatal("a refused command talked to the server")
	}
	if list, _ := h.store.Confirmations(); len(list) != 0 {
		t.Fatal("a refused command wrote records")
	}
}

func TestMainUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"sign"}, {"run", "--tenant", "x"}, {"promote", "--first", "--manual"}, {"confirm", "extra-arg"}, {"trust-builder", "--revoke", "--name", "x"},
		{"trust-builder", "--builder", "amos-builder", "--builder-id", "mch_builderXYZ01"}, {"trust-builder", "--revoke", "--builder", "amos-builder"},
		{"trust-peer", "--peer", "amos-signer-b", "--reason", "why"}, {"trust-recovery", "--recovery-sha256", "abcd"}, {"trust-recovery", "--peer", "x"},
		{"enroll", "--tenant", "x"}, {"enroll-init", "extra"}} {
		var stdout, stderr bytes.Buffer
		if code := Main(args, os.Stdin, &stdout, &stderr, func(string) string { return "" }); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestTrustAndRevokeBuilder(t *testing.T) {
	h := newHarness(t, harnessOptions{noBuilder: true})
	builder := testfixture.NewBuilder(t)
	id := "mch_builderNEW00001"
	err := TrustBuilder(h.operatorEnv(newTerm("ops-bob", builder.SHA256(), testfixture.Hex64('1'), "", id)), id, "amos-builder")
	if !errors.Is(err, ErrAborted) {
		t.Fatalf("mismatched pastes: %v", err)
	}
	term := newTerm("ops-bob", builder.SHA256(), colonUpper(builder.SHA256()), "read from build-agent show-key on amos", id)
	if err := TrustBuilder(h.operatorEnv(term), id, "amos-builder"); err != nil {
		t.Fatalf("TrustBuilder: %v", err)
	}
	list, _ := h.store.TrustedBuilders()
	if len(list) != 1 || list[0].BuilderID != id || list[0].Ed25519PublicKeySHA256 != builder.SHA256() || list[0].Operator != "ops-bob" {
		t.Fatalf("builders: %+v", list)
	}
	if err := RevokeBuilder(h.operatorEnv(newTerm("ops-bob", "mch_wrong")), id, "machine rebuilt"); !errors.Is(err, ErrAborted) {
		t.Fatalf("revoke with the wrong id typed: %v", err)
	}
	if err := RevokeBuilder(h.operatorEnv(newTerm("ops-bob", id)), id, "machine rebuilt"); err != nil {
		t.Fatal(err)
	}
	if list, _ := h.store.TrustedBuilders(); len(list) != 0 {
		t.Fatalf("builder still trusted: %+v", list)
	}
	if err := TrustBuilder(h.operatorEnv(newTerm()), "not an id", "amos-builder"); err == nil {
		t.Fatal("accepted a malformed builder id")
	}
}

// oldPrimary 造一台"旧主"：独立的状态目录与记录，交付了 46、签出 47 但没完成、预留了 48。
func oldPrimary(t *testing.T) (signedPath string, ed25519SHA string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keys, _, err := InitState(dir, "amos-signer-old")
	if err != nil {
		t.Fatal(err)
	}
	store, err := records.Open(dir, keys.Ed25519)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cert := sharedTenantKey(t).CertificateSHA256
	for i, vc := range []int64{46, 47, 48} {
		r := records.Reservation{JobID: "bld_oldPRIMARY000" + string(rune('1'+i)), SignAttempt: 1, TenantSlug: "AnyFun",
			PackageName: testfixture.PackageName, CertificateSHA256: cert, VersionCode: vc, UnsignedSHA256: testfixture.Hex64(byte('1' + i))}
		if _, err := store.Reserve(r, testLimits); err != nil {
			t.Fatal(err)
		}
	}
	must(t, store.MarkSigned("bld_oldPRIMARY0001", testfixture.Hex64('1'), testfixture.Hex64('9')))
	must(t, store.Complete("bld_oldPRIMARY0001", testfixture.Hex64('1'), testfixture.Hex64('9'), "rel_oldRELEASE01"))
	must(t, store.MarkSigned("bld_oldPRIMARY0002", testfixture.Hex64('2'), testfixture.Hex64('8')))
	return filepath.Join(dir, records.SignedFileName), keys.Ed25519SHA256()
}

func TestPromoteImport(t *testing.T) {
	path, oldSHA := oldPrimary(t)
	h := newHarness(t, harnessOptions{role: records.RoleStandby})
	// 备为了验证生成签名信任着旧主；另有一台受信的签名闸不受影响
	must(t, h.store.TrustPeer(records.PeerTrust{Name: "amos-signer-old", X25519PublicKeySHA256: testfixture.Hex64('4'), Ed25519PublicKeySHA256: oldSHA, Mode: records.TrustModeOperator, Operator: "ops"}))
	must(t, h.store.TrustPeer(records.PeerTrust{Name: "amos-signer-c", X25519PublicKeySHA256: testfixture.Hex64('5'), Ed25519PublicKeySHA256: testfixture.Hex64('6'), Mode: records.TrustModeOperator, Operator: "ops"}))
	if err := Promote(h.operatorEnv(newTerm("ops-carol", "old primary is gone", testfixture.Hex64('7'))), PromoteImport, path); err == nil {
		t.Fatal("imported with a fingerprint that is not the old primary's")
	}
	if role, _ := h.store.Role(); role.Role != records.RoleStandby {
		t.Fatal("a failed import changed the role")
	}
	if peers, _ := h.store.TrustedPeers(); len(peers) != 2 {
		t.Fatal("a failed import revoked a signing gate")
	}
	if err := Promote(h.operatorEnv(newTerm("ops-carol", "old primary is gone", h.keys.Ed25519SHA256())), PromoteImport, path); err == nil {
		t.Fatal("imported this machine's own key")
	}
	term := newTerm("ops-carol", "old primary disk failed", oldSHA, testMachine)
	if err := Promote(h.operatorEnv(term), PromoteImport, path); err != nil {
		t.Fatalf("Promote: %v\n%s", err, term.out.String())
	}
	role, _ := h.store.Role()
	if role.Role != records.RolePrimary || role.Mode != records.RoleModeImportFile || role.PreviousPrimaryEd25519SHA256 != oldSHA {
		t.Fatalf("role: %+v", role)
	}
	view, _ := h.store.SignedState(testfixture.PackageName, h.key.CertificateSHA256, "bld_newJOB00000001", testfixture.Hex64('5'))
	if !view.HasMax || view.Max != 48 {
		t.Fatalf("imported max: %+v", view)
	}
	if !strings.Contains(term.out.String(), "3 reservations (2 not completed), highest versionCode 48") || !strings.Contains(term.out.String(), "last line sha256") {
		t.Fatalf("import summary:\n%s", term.out.String())
	}
	// 评审 P1-3：被取代的旧主从本机信任里撤销（提示在输入机器名确认之前显示）
	out := term.out.String()
	notice := strings.Index(out, "amos-signer-old")
	if peers, _ := h.store.TrustedPeers(); len(peers) != 1 || peers[0].Name != "amos-signer-c" {
		t.Fatalf("the superseded primary is still trusted: %+v", peers)
	}
	if notice < 0 || notice > strings.Index(out, "Type this machine's name") || !strings.Contains(out, "reinstall it as a new machine") {
		t.Fatalf("promote output does not announce the revocation first:\n%s", out)
	}
	// 旧主签出 47 没完成：新主能续签同一任务，签名状态随导入保留（不能释放），别的任务签不了 47
	existing, err := h.store.Reserve(records.Reservation{JobID: "bld_oldPRIMARY0002", SignAttempt: 2, TenantSlug: "AnyFun", PackageName: testfixture.PackageName,
		CertificateSHA256: h.key.CertificateSHA256, VersionCode: 47, UnsignedSHA256: testfixture.Hex64('2')}, testLimits)
	if err != nil || existing == nil || existing.Status != records.StatusSigned || existing.SignedSHA256 != testfixture.Hex64('8') {
		t.Fatalf("resume: %+v %v", existing, err)
	}
	if _, err := h.store.Abandon("bld_oldPRIMARY0002", "ops", "try"); !errors.Is(err, records.ErrAlreadySigned) {
		t.Fatalf("released an imported signed reservation: %v", err)
	}
	if err := Promote(h.operatorEnv(newTerm("ops", "again", testMachine)), PromoteFirst, ""); err == nil {
		t.Fatal("promoted a primary again")
	}
}

func TestPromoteManualAndFirst(t *testing.T) {
	h := newHarness(t, harnessOptions{role: records.RoleStandby})
	oldEd := testfixture.Hex64('7')
	must(t, h.store.TrustPeer(records.PeerTrust{Name: "amos-signer-old", X25519PublicKeySHA256: testfixture.Hex64('4'), Ed25519PublicKeySHA256: oldEd, Mode: records.TrustModeOperator, Operator: "ops"}))
	term := newTerm("ops-dave", "old primary lost", "52", oldEd, testMachine)
	if err := Promote(h.operatorEnv(term), PromoteManual, ""); err != nil {
		t.Fatalf("manual: %v\n%s", err, term.out.String())
	}
	if peers, _ := h.store.TrustedPeers(); len(peers) != 0 {
		t.Fatalf("promote --manual with the old primary's fingerprint kept trusting it: %+v", peers)
	}
	// 没给旧主指纹：不猜，列出受信签名闸，提示运维自己撤销
	noPrev := newHarness(t, harnessOptions{role: records.RoleStandby})
	must(t, noPrev.store.TrustPeer(records.PeerTrust{Name: "amos-signer-old", X25519PublicKeySHA256: testfixture.Hex64('4'), Ed25519PublicKeySHA256: oldEd, Mode: records.TrustModeOperator, Operator: "ops"}))
	noPrevTerm := newTerm("ops-dave", "old primary lost", "52", "", testMachine)
	if err := Promote(noPrev.operatorEnv(noPrevTerm), PromoteManual, ""); err != nil {
		t.Fatalf("manual without the old primary: %v", err)
	}
	if peers, _ := noPrev.store.TrustedPeers(); len(peers) != 1 || !strings.Contains(noPrevTerm.out.String(), "trust-peer --revoke --peer amos-signer-old") {
		t.Fatalf("peers %+v output:\n%s", peers, noPrevTerm.out.String())
	}
	view, _ := h.store.SignedState(testfixture.PackageName, h.key.CertificateSHA256, "bld_x0000001", testfixture.Hex64('1'))
	if !view.HasMax || view.Max != 52 {
		t.Fatalf("baseline: %+v", view)
	}
	if role, _ := h.store.Role(); role.Mode != records.RoleModeManual {
		t.Fatalf("role: %+v", role)
	}

	fresh := newHarness(t, harnessOptions{role: records.RoleStandby})
	if err := Promote(fresh.operatorEnv(newTerm("ops", "first primary", "wrong-name")), PromoteFirst, ""); !errors.Is(err, ErrAborted) {
		t.Fatalf("wrong machine name: %v", err)
	}
	if err := Promote(fresh.operatorEnv(newTerm("ops", "first primary", testMachine)), PromoteFirst, ""); err != nil {
		t.Fatal(err)
	}
	if role, _ := fresh.store.Role(); role.Role != records.RolePrimary || role.Mode != records.RoleModeInitial {
		t.Fatalf("role: %+v", role)
	}

	withHistory := newHarness(t, harnessOptions{role: records.RoleStandby})
	must(t, withHistory.store.SetBaseline(records.Baseline{PackageName: testfixture.PackageName, CertificateSHA256: withHistory.key.CertificateSHA256, MaxVersionCode: 3, Operator: "ops"}))
	if err := Promote(withHistory.operatorEnv(newTerm("ops", "first primary", testMachine)), PromoteFirst, ""); err == nil {
		t.Fatal("--first accepted a machine with signing history")
	}

	// 本机接受过别的签名闸生成的密钥：之前有过主，--first 会跳过它的签名记录
	followed := newHarness(t, harnessOptions{role: records.RoleStandby, noConfirm: true})
	p := newPeerMachine(t, "amos-signer-main", "mch_signerM0001")
	must(t, followed.store.TrustPeer(p.trust(records.TrustModeOperator)))
	g := generateFor(t, "kgr_followed00001", p.ed, binding(followed.digest, 140, ""), followed.keys.X25519PublicKey())
	followed.server.items = []map[string]any{followed.generatedItem(g, "kgr_followed00001", p.name, p.id, p.edPub(), followed.roots)}
	followed.useGeneratedKey(g)
	must(t, followed.runner.RunChecks(context.Background()))
	if conf, _, _ := followed.store.ActiveConfirmation(testfixture.PackageName); conf.Mode != records.ConfirmModePeerGenerated {
		t.Fatalf("setup: %+v", conf)
	}
	err := Promote(followed.operatorEnv(newTerm("ops", "first primary", testMachine)), PromoteFirst, "")
	if err == nil || !strings.Contains(err.Error(), "amos-signer-main") || !strings.Contains(err.Error(), "--import") {
		t.Fatalf("--first on a standby that followed a primary: %v", err)
	}
	if role, _ := followed.store.Role(); role.Role != records.RoleStandby {
		t.Fatal("a refused --first changed the role")
	}
}

func TestAbandon(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	r := records.Reservation{JobID: "bld_abandonJOB0001", SignAttempt: 1, TenantSlug: "AnyFun", PackageName: testfixture.PackageName,
		CertificateSHA256: h.key.CertificateSHA256, VersionCode: 46, UnsignedSHA256: testfixture.Hex64('1')}
	if _, err := h.store.Reserve(r, testLimits); err != nil {
		t.Fatal(err)
	}
	if err := Abandon(h.operatorEnv(newTerm("ops", "bld_other")), r.JobID, "never delivered"); !errors.Is(err, ErrAborted) {
		t.Fatalf("wrong job typed: %v", err)
	}
	term := newTerm("ops-erin", r.JobID)
	if err := Abandon(h.operatorEnv(term), r.JobID, "apksigner never ran"); err != nil {
		t.Fatal(err)
	}
	if got := h.reservation(r.JobID); got.Status != records.StatusAbandoned {
		t.Fatalf("status: %+v", got)
	}
	r2 := r
	r2.JobID, r2.UnsignedSHA256 = "bld_abandonJOB0002", testfixture.Hex64('2')
	if _, err := h.store.Reserve(r2, testLimits); err != nil {
		t.Fatalf("versionCode not released: %v", err)
	}
	// 记下了签名包：那个包可能已经在服务端，不能释放
	must(t, h.store.MarkSigned(r2.JobID, r2.UnsignedSHA256, testfixture.Hex64('9')))
	if err := Abandon(h.operatorEnv(newTerm("ops", r2.JobID)), r2.JobID, "too late"); err == nil || !strings.Contains(err.Error(), "signed package") {
		t.Fatalf("released a signed reservation: %v", err)
	}
	must(t, h.store.Complete(r2.JobID, r2.UnsignedSHA256, testfixture.Hex64('9'), "rel_x1234"))
	if err := Abandon(h.operatorEnv(newTerm("ops", r2.JobID)), r2.JobID, "too late"); err == nil {
		t.Fatal("released a delivered reservation")
	}
}

// abandon、promote 与正在处理任务的 signer run 竞争：必须先停服务。confirm、trust-builder 不必。
func TestExclusiveOperatorCommandsNeedTheRunLock(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	env := map[string]string{
		EnvServerURL: h.server.srv.URL, EnvMachineToken: testToken, EnvName: testMachine, EnvStateDir: h.cfg.StateDir,
	}
	getenv := func(k string) string { return env[k] }
	lock, err := AcquireRunLock(h.cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	fn := func(OperatorEnv) error { called++; return nil }
	if err := runOperator(newTerm(), getenv, NeedLocal, exclusive, fn); err == nil || called != 0 || !strings.Contains(err.Error(), "systemctl stop") {
		t.Fatalf("exclusive command while signer run holds the lock: %v (called %d)", err, called)
	}
	if err := runOperator(newTerm(), getenv, NeedLocal, shared, fn); err != nil || called != 1 {
		t.Fatalf("shared command: %v (called %d)", err, called)
	}
	lock.Close()
	if err := runOperator(newTerm(), getenv, NeedLocal, exclusive, fn); err != nil || called != 2 {
		t.Fatalf("exclusive command after the service stopped: %v (called %d)", err, called)
	}
	// 运维命令拿着锁时 signer run 起不来
	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runOperator(newTerm(), getenv, NeedLocal, exclusive, func(OperatorEnv) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	_, err = AcquireRunLock(h.cfg.StateDir)
	close(release)
	if err == nil {
		t.Fatal("signer run started while abandon or promote was running")
	}
	must(t, <-done)
}

func TestListAndShowKey(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	var out bytes.Buffer
	if err := List(&out, h.keys, h.store); err != nil {
		t.Fatal(err)
	}
	trustTip, signedTip, err := h.store.Tips()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{testMachine, h.key.CertificateSHA256, h.digest, h.builder.ID, "role primary", trustTip.LastHash, signedTip.LastHash} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("list output misses %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	if err := ShowKey(&out, testMachine, h.keys, records.RolePrimary); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var entry pins.Signer
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("the last line is not a pin entry: %v", err)
	}
	if err := entry.Validate(); err != nil || entry.X25519PublicKeySHA256 != h.keys.X25519SHA256() || entry.Ed25519PublicKeySHA256 != h.keys.Ed25519SHA256() || entry.Role != pins.RolePrimary {
		t.Fatalf("pin entry: %+v %v", entry, err)
	}
	file, err := pins.Parse([]byte(`{"format":"rn-signer-pins/v1","signers":[` + lines[len(lines)-1] + `]}`))
	if err != nil || len(file.Signers) != 1 {
		t.Fatalf("pasting the entry into a pin file: %v", err)
	}
}
