package signer

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/internal/testfixture"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/records"
	"github.com/Helix2010/RN-Server/signing/trustroots"
)

// ---- trust-peer / trust-recovery / trust-builder --builder ----

func TestTrustPeerCommand(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{})
	b := newPeerMachine(t, "amos-signer-b", "mch_signerB0001")
	c := newPeerMachine(t, "amos-signer-c", "mch_signerC0001")
	h.server.peers = PeersResponse{Signers: []PeerSigner{b.view("standby"), c.view("standby")}}

	term := newTerm("ops-alice", colonUpper(b.xSHA()), b.edSHA(), "from the install output", "amos-signer-b")
	if err := TrustPeer(ctx, h.operatorEnv(term), "amos-signer-b"); err != nil {
		t.Fatalf("TrustPeer: %v\n%s", err, term.out.String())
	}
	// 粘贴之前不显示指纹：运维要从那台机器的安装输出里抄，不是从屏幕上抄
	out := term.out.String()
	beforePaste := out[:strings.Index(out, "Paste its X25519")]
	if strings.Contains(beforePaste, b.xSHA()) || strings.Contains(beforePaste, b.edSHA()) || !strings.Contains(beforePaste, "mch_signerB0001") {
		t.Fatalf("output before the paste:\n%s", beforePaste)
	}
	peers, _ := h.store.TrustedPeers()
	if len(peers) != 1 || peers[0].Name != "amos-signer-b" || peers[0].X25519PublicKeySHA256 != b.xSHA() || peers[0].Mode != records.TrustModeOperator || peers[0].Note != "from the install output" {
		t.Fatalf("peers: %+v", peers)
	}

	refusals := map[string]struct {
		name  string
		lines []string
		want  string
	}{
		"pasted x25519 differs":  {"amos-signer-c", []string{"ops-alice", b.xSHA(), c.edSHA(), "", "amos-signer-c"}, "do not match"},
		"pasted ed25519 differs": {"amos-signer-c", []string{"ops-alice", c.xSHA(), b.edSHA(), "", "amos-signer-c"}, "do not match"},
		"not a fingerprint":      {"amos-signer-c", []string{"ops-alice", "yes"}, "64-character"},
		"typed name differs":     {"amos-signer-c", []string{"ops-alice", c.xSHA(), c.edSHA(), "", "amos-signer-b"}, "aborted"},
		"not on the server":      {"amos-signer-d", []string{"ops-alice"}, "no active signing gate"},
		"this machine":           {testMachine, []string{"ops-alice"}, "trusts itself"},
	}
	for name, r := range refusals {
		term := newTerm(r.lines...)
		err := TrustPeer(ctx, h.operatorEnv(term), r.name)
		if err == nil || !strings.Contains(err.Error(), r.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// 服务端给的公钥与指纹对不上：不显示、不用
	bad := c.view("standby")
	bad.X25519PublicKey = b.view("standby").X25519PublicKey
	h.server.peers.Signers[1] = bad
	if err := TrustPeer(ctx, h.operatorEnv(newTerm("ops-alice")), "amos-signer-c"); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("malformed server record: %v", err)
	}
	if peers, _ := h.store.TrustedPeers(); len(peers) != 1 {
		t.Fatalf("a refused trust-peer wrote a record: %+v", peers)
	}

	trust, err := LocalTrust(h.keys, h.store)
	if err != nil || len(trust.Signers) != 2 || trust.Signers[0].Name != testMachine || trust.Signers[0].X25519SHA256 != h.keys.X25519SHA256() ||
		trust.Signers[1].Ed25519SHA256 != b.edSHA() || len(trust.Builders) != 1 {
		t.Fatalf("LocalTrust: %+v %v", trust, err)
	}

	if err := RevokePeer(h.operatorEnv(newTerm("ops-alice", "amos-signer-b")), "amos-signer-b", "machine rebuilt"); err != nil {
		t.Fatal(err)
	}
	if peers, _ := h.store.TrustedPeers(); len(peers) != 0 {
		t.Fatalf("revoked peer is still trusted: %+v", peers)
	}
}

func TestTrustRecoveryCommand(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{})
	r := newRecoveryKeyPair(t, "platform-recovery")
	revoked := newRecoveryKeyPair(t, "old-recovery")
	revoked.view.Revoked = true
	h.server.peers = PeersResponse{RecoveryKeys: []PeerRecoveryKey{r.view, revoked.view}}

	term := newTerm("ops-alice", colonUpper(r.view.X25519PublicKeySHA256), "", "platform-recovery")
	if err := TrustRecovery(ctx, h.operatorEnv(term)); err != nil {
		t.Fatalf("TrustRecovery: %v\n%s", err, term.out.String())
	}
	keys, _ := h.store.TrustedRecoveryKeys()
	if len(keys) != 1 || keys[0].Name != "platform-recovery" || keys[0].X25519PublicKeySHA256 != r.view.X25519PublicKeySHA256 || keys[0].Mode != records.TrustModeOperator {
		t.Fatalf("recovery keys: %+v", keys)
	}
	for name, lines := range map[string][]string{
		"unknown key":  {"ops-alice", strings.Repeat("ab", 32)},
		"revoked key":  {"ops-alice", revoked.view.X25519PublicKeySHA256},
		"typed name":   {"ops-alice", r.view.X25519PublicKeySHA256, "", "old-recovery"},
		"not hex":      {"ops-alice", "platform-recovery"},
		"control char": {"ops-alice", "\x1b[2J"},
	} {
		if err := TrustRecovery(ctx, h.operatorEnv(newTerm(lines...))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if keys, _ := h.store.TrustedRecoveryKeys(); len(keys) != 1 {
		t.Fatalf("a refused trust-recovery wrote a record: %+v", keys)
	}
	if err := RevokeRecovery(h.operatorEnv(newTerm("ops-alice", strings.Repeat("ab", 32))), r.view.X25519PublicKeySHA256, "rotated"); !errors.Is(err, ErrAborted) {
		t.Fatalf("revoke with a different second paste: %v", err)
	}
	if err := RevokeRecovery(h.operatorEnv(newTerm("ops-alice", r.view.X25519PublicKeySHA256)), r.view.X25519PublicKeySHA256, "rotated to a new key"); err != nil {
		t.Fatal(err)
	}
	if keys, _ := h.store.TrustedRecoveryKeys(); len(keys) != 0 {
		t.Fatalf("revoked recovery key is still trusted: %+v", keys)
	}
}

func TestTrustBuilderByName(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{noBuilder: true})
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sha := fingerprint.SHA256Hex(pub)
	h.server.peers = PeersResponse{Builders: []PeerBuilder{{MachineID: "mch_builderNEW0001", Name: "amos-builder-2", Status: "active",
		PublicKey: base64.StdEncoding.EncodeToString(pub), PublicKeySHA256: sha}}}
	term := newTerm("ops-alice", sha, "", "amos-builder-2")
	if err := TrustBuilderByName(ctx, h.operatorEnv(term), "amos-builder-2"); err != nil {
		t.Fatalf("TrustBuilderByName: %v\n%s", err, term.out.String())
	}
	if strings.Contains(term.out.String()[:strings.Index(term.out.String(), "Paste the builder")], sha) {
		t.Fatal("the builder fingerprint was shown before the paste")
	}
	builders, _ := h.store.TrustedBuilders()
	if len(builders) != 1 || builders[0].BuilderID != "mch_builderNEW0001" || builders[0].Name != "amos-builder-2" || builders[0].Ed25519PublicKeySHA256 != sha {
		t.Fatalf("builders: %+v", builders)
	}
	if err := TrustBuilderByName(ctx, h.operatorEnv(newTerm("ops-alice", strings.Repeat("cd", 32))), "amos-builder-2"); !errors.Is(err, ErrAborted) {
		t.Fatalf("mismatched paste: %v", err)
	}
	if err := TrustBuilderByName(ctx, h.operatorEnv(newTerm("ops-alice")), "amos-builder-9"); err == nil {
		t.Fatal("trusted a builder the server does not know")
	}
}

// ---- 主签名闸生成 ----

// generationItem 是只下发给主签名闸的租户项：还没有密钥（box 为 null），带生成请求。
func generationItem(requestID string, roots trustroots.Roots, published any) map[string]any {
	digest, _ := trustroots.Digest(roots)
	return map[string]any{
		"tenantSlug": testfixture.TenantSlug, "keystoreVersion": 0, "packageName": nil, "certificateSha256": nil, "keyAlias": nil, "box": nil,
		"trustRoots": roots, "trustRootsDigest": digest, "generator": nil, "generationSignature": nil,
		"generationRequest": map[string]any{"requestId": requestID, "packageName": testfixture.PackageName, "alias": testAlias,
			"trustRoots": roots, "trustRootsDigest": digest, "publishedMaxBuildNumber": published},
	}
}

// generatedItem 是服务端落库后给某台签名闸的租户项：发给它的 Box、生成者、生成签名、请求 id 与完整 Upload。
func (h *harness) generatedItem(g GeneratedKeystore, requestID string, generatorName, generatorID string, generatorPub ed25519.PublicKey, roots trustroots.Roots, published int64) map[string]any {
	h.t.Helper()
	box, ok := g.Upload.BoxFor(h.keys.X25519SHA256())
	if !ok {
		h.t.Fatal("the generated keystore is not encrypted to this signing gate")
	}
	digest, _ := trustroots.Digest(roots)
	return map[string]any{
		"tenantSlug": testfixture.TenantSlug, "keystoreVersion": 7, "packageName": g.Upload.PackageName, "certificateSha256": g.CertificateSHA256,
		"keyAlias": serverAlias, "box": box, "trustRoots": roots, "trustRootsDigest": digest, "generationRequest": nil,
		"generator": map[string]any{"machineId": generatorID, "name": generatorName, "ed25519PublicKey": base64.StdEncoding.EncodeToString(generatorPub),
			"ed25519PublicKeySha256": fingerprint.SHA256Hex(generatorPub)},
		"generationSignature": g.Signature, "generationRequestId": requestID, "upload": g.Upload, "publishedMaxBuildNumber": published,
	}
}

// useGeneratedKey 让假 apksigner 按新密钥的口令与证书工作（试签用）。
func (h *harness) useGeneratedKey(g GeneratedKeystore) {
	h.t.Helper()
	box, _ := g.Upload.BoxFor(h.keys.X25519SHA256())
	plain, err := keystorebox.Open(box, h.keys.X25519.Bytes())
	if err != nil {
		h.t.Fatal(err)
	}
	h.signer.mu.Lock()
	h.signer.password, h.signer.cert = plain.StorePassword, g.CertificateSHA256
	h.signer.mu.Unlock()
}

func (h *harness) lastReport() CheckReport {
	h.t.Helper()
	h.server.mu.Lock()
	defer h.server.mu.Unlock()
	if len(h.server.reports) == 0 || len(h.server.reports[len(h.server.reports)-1]) == 0 {
		h.t.Fatalf("no check report; logs:\n%s", h.logs.String())
	}
	last := h.server.reports[len(h.server.reports)-1]
	return last[len(last)-1]
}

func generateFor(t *testing.T, requestID string, generator ed25519.PrivateKey, recipients ...[]byte) GeneratedKeystore {
	t.Helper()
	g, err := GenerateKeystore(GenerateParams{RequestID: requestID, TenantSlug: testfixture.TenantSlug, PackageName: testfixture.PackageName,
		KeyAlias: testAlias, Recipients: recipients, Generator: generator, KeyBits: 2048, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func recipientsOf(u keystorebox.Upload) []string {
	var out []string
	for _, b := range u.Boxes {
		out = append(out, b.RecipientSHA256)
	}
	sort.Strings(out)
	return out
}

// 首次信任：只加密给本机、本机信任的签名闸与恢复公钥（服务端多登记的不加），签生成签名交回，
// 服务端接受后写自动确认；服务端落库后下一轮试签就绪。
func TestPrimaryGeneratesWithFirstTrust(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{noConfirm: true})
	h.server.activeKey, h.server.activeEdKey = h.keys.X25519SHA256(), h.keys.Ed25519SHA256()
	b := newPeerMachine(t, "amos-signer-b", "mch_signerB0001")
	extra := newPeerMachine(t, "rogue-signer", "mch_signerR0001")
	r := newRecoveryKeyPair(t, "platform-recovery")
	rogueRecovery := newRecoveryKeyPair(t, "rogue-recovery")
	must(t, h.store.TrustPeer(b.trust(records.TrustModeOperator)))
	must(t, h.store.TrustRecovery(r.trust()))
	self := PeerSigner{MachineID: "mch_signerA0001", Name: testMachine, Status: "active",
		X25519PublicKey: base64.StdEncoding.EncodeToString(h.keys.X25519PublicKey()), X25519PublicKeySHA256: h.keys.X25519SHA256(),
		Ed25519PublicKey: base64.StdEncoding.EncodeToString(h.keys.Ed25519PublicKey()), Ed25519PublicKeySHA256: h.keys.Ed25519SHA256()}
	h.server.peers = PeersResponse{Signers: []PeerSigner{self, b.view("standby"), extra.view("standby")}, RecoveryKeys: []PeerRecoveryKey{r.view, rogueRecovery.view}}
	h.server.items = []map[string]any{generationItem("kgr_first0000001", h.roots, 57)}

	must(t, h.runner.RunChecks(ctx))
	if len(h.server.failures) != 0 || h.server.submitCalls != 1 {
		t.Fatalf("failures %+v submits %d; logs:\n%s", h.server.failures, h.server.submitCalls, h.logs.String())
	}
	sub := h.server.submissions["kgr_first0000001"]
	if err := keystorebox.VerifyGeneration(h.keys.Ed25519PublicKey(), "kgr_first0000001", sub.Upload, sub.Signature); err != nil {
		t.Fatalf("generation signature: %v", err)
	}
	if sub.Generator.MachineID != "mch_signerA0001" || sub.Generator.Ed25519PublicKeySHA256 != h.keys.Ed25519SHA256() {
		t.Fatalf("generator: %+v", sub.Generator)
	}
	want := []string{h.keys.X25519SHA256(), b.xSHA(), r.view.X25519PublicKeySHA256}
	sort.Strings(want)
	if got := recipientsOf(sub.Upload); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("recipients %v, want %v (the rogue signer %s and recovery key %s must not be recipients)", got, want, extra.xSHA(), rogueRecovery.view.X25519PublicKeySHA256)
	}
	for name, key := range map[string][]byte{"standby": b.x.Bytes(), "recovery": r.priv.Bytes()} {
		box, _ := sub.Upload.BoxFor(fingerprint.SHA256Hex(mustPublic(t, key)))
		plain, err := keystorebox.Open(box, key)
		if err != nil || plain.CertificateSHA256 != sub.Upload.CertificateSHA256 || strings.Join(plain.Recipients, ",") != strings.Join(want, ",") {
			t.Fatalf("%s cannot open its box: %v", name, err)
		}
	}
	conf, ok, _ := h.store.ActiveConfirmation(testfixture.PackageName)
	if !ok || conf.Mode != records.ConfirmModeFirstGeneration || conf.ConfirmedBy != "auto:first-generation" || conf.CertificateSHA256 != sub.Upload.CertificateSHA256 ||
		!trustroots.Equal(conf.TrustRoots, h.roots) || conf.MinSDK != 24 || conf.TargetSDK != 28 || conf.FirstSignMaxVersionCode != 157 ||
		conf.KeystoreVersion != 7 || conf.GeneratorName != testMachine || conf.GenerationRequestID != "kgr_first0000001" || conf.KeyAlias != testAlias {
		t.Fatalf("confirmation: %+v", conf)
	}
	trust := h.server.trusts[len(h.server.trusts)-1]
	if len(trust.Signers) != 2 || trust.Signers[1].Name != "amos-signer-b" || len(trust.RecoveryKeys) != 1 || trust.RecoveryKeys[0] != r.view.X25519PublicKeySHA256 || len(trust.Builders) != 1 {
		t.Fatalf("trust report: %+v", trust)
	}

	// 同一个请求（服务端还没来得及更新）不重复生成
	must(t, h.runner.RunChecks(ctx))
	if h.server.submitCalls != 1 {
		t.Fatalf("the same generation request was processed twice: %d", h.server.submitCalls)
	}

	// 服务端落库：下一轮（不等 ChecksInterval）解开发给本机的新密钥、确认已在、试签、就绪
	h.server.mu.Lock()
	h.server.items = []map[string]any{h.generatedItem(GeneratedKeystore{Upload: sub.Upload, Signature: sub.Signature, CertificateSHA256: sub.Upload.CertificateSHA256},
		"kgr_first0000001", testMachine, "mch_signerA0001", h.keys.Ed25519PublicKey(), h.roots, 57)}
	h.server.mu.Unlock()
	h.useGeneratedKey(GeneratedKeystore{Upload: sub.Upload, CertificateSHA256: sub.Upload.CertificateSHA256})
	h.runner.lastChecks = time.Now()
	h.runOnce()
	rep := h.lastReport()
	if rep.Decrypt != "ok" || !rep.Confirmed || rep.TrialSign != "ok" || rep.Error != nil || rep.KeystoreVersion != 7 {
		t.Fatalf("report after the server stored the key: %+v; logs:\n%s", rep, h.logs.String())
	}
	if ready := h.runner.Ready(); len(ready) != 1 || ready[0].CertificateSHA256 != sub.Upload.CertificateSHA256 {
		t.Fatalf("ready: %+v", ready)
	}
}

func mustPublic(t *testing.T, x25519Private []byte) []byte {
	t.Helper()
	k, err := ecdh.X25519().NewPrivateKey(x25519Private)
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

// 已确认的包名换密钥：沿用本机确认的信任根与 SDK 下限，首签上限取本机签名历史 + 100，旧证书被取代。
func TestPrimaryRegeneratesWithConfirmedTrustRoots(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, harnessOptions{})
	r := newRecoveryKeyPair(t, "platform-recovery")
	must(t, h.store.TrustRecovery(r.trust()))
	h.server.peers = PeersResponse{RecoveryKeys: []PeerRecoveryKey{r.view}}
	_, err := h.store.Reserve(records.Reservation{JobID: "bld_historyJOB0001", SignAttempt: 1, TenantSlug: testfixture.TenantSlug, PackageName: testfixture.PackageName,
		CertificateSHA256: h.key.CertificateSHA256, VersionCode: 80, UnsignedSHA256: strings.Repeat("1", 64)}, testLimits)
	must(t, err)
	old, _, _ := h.store.ActiveConfirmation(testfixture.PackageName)
	// 服务端给的信任根只作对照：发来的请求里 minSdk 等信息不存在，沿用的是本机记录
	h.server.items[0]["generationRequest"] = generationItem("kgr_regen0000001", h.roots, 5)["generationRequest"]
	must(t, h.runner.RunChecks(ctx))
	sub, ok := h.server.submissions["kgr_regen0000001"]
	if !ok || len(h.server.failures) != 0 {
		t.Fatalf("no submission; failures %+v; logs:\n%s", h.server.failures, h.logs.String())
	}
	conf, _, _ := h.store.ActiveConfirmation(testfixture.PackageName)
	if conf.Mode != records.ConfirmModeRegenerated || conf.ConfirmedBy != "auto:regenerated" || conf.CertificateSHA256 != sub.Upload.CertificateSHA256 ||
		conf.TargetSDK != old.TargetSDK || conf.MinSDK != old.MinSDK || conf.TrustRootsDigest != old.TrustRootsDigest || conf.FirstSignMaxVersionCode != 180 {
		t.Fatalf("confirmation: %+v (old %+v)", conf, old)
	}
	if _, ok, _ := h.store.Confirmation(testfixture.PackageName, h.key.CertificateSHA256); ok {
		t.Fatal("the old certificate is still confirmed")
	}
	if got := recipientsOf(sub.Upload); len(got) != 2 {
		t.Fatalf("recipients: %v", got)
	}
}

func TestPrimaryRefusesToGenerate(t *testing.T) {
	ctx := context.Background()
	changed := func(h *harness) trustroots.Roots {
		roots := h.roots
		roots.APIBaseURL = "https://api.attacker.example"
		roots.AppLinksHosts = []string{"api.attacker.example"}
		roots, _ = roots.Normalize()
		return roots
	}
	cases := map[string]struct {
		opts  harnessOptions
		setup func(*harness, recoveryKeyPair)
		code  string
	}{
		"trust roots digest changed": {harnessOptions{}, func(h *harness, r recoveryKeyPair) {
			h.server.items[0]["generationRequest"] = generationItem("kgr_refuse000001", changed(h), 5)["generationRequest"]
		}, GenerationTrustRootsChanged},
		"package confirmed for another tenant": {harnessOptions{}, func(h *harness, r recoveryKeyPair) {
			item := generationItem("kgr_refuse000001", h.roots, 5)
			item["tenantSlug"] = "Predict"
			h.server.items = []map[string]any{item}
		}, GenerationTrustRootsChanged},
		"no recovery key pinned": {harnessOptions{noConfirm: true}, func(h *harness, r recoveryKeyPair) {
			h.server.items = []map[string]any{generationItem("kgr_refuse000001", h.roots, 5)}
		}, GenerationRecoveryKeyNotPinned},
		"pinned recovery key revoked on the server": {harnessOptions{noConfirm: true}, func(h *harness, r recoveryKeyPair) {
			must(t, h.store.TrustRecovery(r.trust()))
			revoked := r.view
			revoked.Revoked = true
			h.server.peers.RecoveryKeys = []PeerRecoveryKey{revoked}
			h.server.items = []map[string]any{generationItem("kgr_refuse000001", h.roots, 5)}
		}, GenerationRecoveryKeyNotPinned},
		"pinned recovery key replaced on the server": {harnessOptions{noConfirm: true}, func(h *harness, r recoveryKeyPair) {
			must(t, h.store.TrustRecovery(r.trust()))
			other := newRecoveryKeyPair(t, "platform-recovery")
			swapped := r.view
			swapped.X25519PublicKey = other.view.X25519PublicKey // 同一个指纹，换了公钥
			h.server.peers.RecoveryKeys = []PeerRecoveryKey{swapped}
			h.server.items = []map[string]any{generationItem("kgr_refuse000001", h.roots, 5)}
		}, GenerationRecoveryKeyNotPinned},
		"standby in its local records": {harnessOptions{role: records.RoleStandby, noConfirm: true}, func(h *harness, r recoveryKeyPair) {
			must(t, h.store.TrustRecovery(r.trust()))
			h.server.items = []map[string]any{generationItem("kgr_refuse000001", h.roots, 5)}
		}, GenerationNotLocalPrimary},
		"first trust with a wrong server digest": {harnessOptions{noConfirm: true}, func(h *harness, r recoveryKeyPair) {
			must(t, h.store.TrustRecovery(r.trust()))
			item := generationItem("kgr_refuse000001", h.roots, 5)
			item["generationRequest"].(map[string]any)["trustRootsDigest"] = strings.Repeat("0", 64)
			h.server.items = []map[string]any{item}
		}, GenerationFailed},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, c.opts)
			r := newRecoveryKeyPair(t, "platform-recovery")
			h.server.peers = PeersResponse{RecoveryKeys: []PeerRecoveryKey{r.view}}
			before, _, _ := h.store.ActiveConfirmation(testfixture.PackageName)
			c.setup(h, r)
			must(t, h.runner.RunChecks(ctx))
			if len(h.server.failures) != 1 || h.server.failures[0].Job != "kgr_refuse000001" || h.server.failures[0].Code != c.code {
				t.Fatalf("failures %+v; logs:\n%s", h.server.failures, h.logs.String())
			}
			if h.server.submitCalls != 0 {
				t.Fatal("submitted a keystore despite the refusal")
			}
			if after, _, _ := h.store.ActiveConfirmation(testfixture.PackageName); after.CertificateSHA256 != before.CertificateSHA256 ||
				after.TrustRootsDigest != before.TrustRootsDigest || after.ConfirmedAt != before.ConfirmedAt {
				t.Fatalf("the confirmation changed: %+v", after)
			}
			// 报过失败的请求不再处理
			must(t, h.runner.RunChecks(ctx))
			if len(h.server.failures) != 1 {
				t.Fatalf("the refusal was reported again: %+v", h.server.failures)
			}
		})
	}
}

func TestGenerationSubmitOutcomes(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) *harness {
		h := newHarness(t, harnessOptions{noConfirm: true})
		r := newRecoveryKeyPair(t, "platform-recovery")
		must(t, h.store.TrustRecovery(r.trust()))
		h.server.peers = PeersResponse{RecoveryKeys: []PeerRecoveryKey{r.view}}
		h.server.items = []map[string]any{generationItem("kgr_submit000001", h.roots, nil)}
		return h
	}
	t.Run("stale request", func(t *testing.T) {
		h := setup(t)
		h.server.submitStatus["kgr_submit000001"] = problem{409, "KEYSTORE_GENERATION_STALE"}
		must(t, h.runner.RunChecks(ctx))
		must(t, h.runner.RunChecks(ctx))
		if h.server.submitCalls != 1 || len(h.server.failures) != 0 {
			t.Fatalf("submits %d failures %+v", h.server.submitCalls, h.server.failures)
		}
		if _, ok, _ := h.store.ActiveConfirmation(testfixture.PackageName); ok {
			t.Fatal("confirmed a keystore the server did not store")
		}
	})
	t.Run("refused by the server", func(t *testing.T) {
		h := setup(t)
		h.server.submitStatus["kgr_submit000001"] = problem{422, "KEYSTORE_GENERATION_SIGNATURE_INVALID"}
		must(t, h.runner.RunChecks(ctx))
		if len(h.server.failures) != 1 || h.server.failures[0].Code != GenerationFailed || !strings.Contains(h.server.failures[0].Detail, "KEYSTORE_GENERATION_SIGNATURE_INVALID") {
			t.Fatalf("failures %+v", h.server.failures)
		}
		if _, ok, _ := h.store.ActiveConfirmation(testfixture.PackageName); ok {
			t.Fatal("confirmed a keystore the server refused")
		}
	})
	t.Run("server unavailable", func(t *testing.T) {
		h := setup(t)
		h.server.submitStatus["kgr_submit000001"] = problem{503, "UNAVAILABLE"}
		must(t, h.runner.RunChecks(ctx))
		first := h.server.submitCalls
		if first != 3 || len(h.server.failures) != 0 {
			t.Fatalf("submits %d (want 1 + 2 retries) failures %+v", first, h.server.failures)
		}
		// 下一轮重新生成、重新交回
		delete(h.server.submitStatus, "kgr_submit000001")
		must(t, h.runner.RunChecks(ctx))
		if h.server.submitCalls != first+1 {
			t.Fatalf("not retried next round: %d", h.server.submitCalls)
		}
		conf, ok, _ := h.store.ActiveConfirmation(testfixture.PackageName)
		if !ok || conf.CertificateSHA256 != h.server.submissions["kgr_submit000001"].Upload.CertificateSHA256 || conf.FirstSignMaxVersionCode != 100 {
			t.Fatalf("confirmation after the retry: %+v", conf)
		}
	})
	t.Run("peer list unavailable", func(t *testing.T) {
		h := setup(t)
		h.server.peersStatus = 503
		must(t, h.runner.RunChecks(ctx))
		if h.server.submitCalls != 0 || len(h.server.failures) != 0 {
			t.Fatalf("submits %d failures %+v", h.server.submitCalls, h.server.failures)
		}
		h.server.peersStatus = 0
		must(t, h.runner.RunChecks(ctx))
		if h.server.submitCalls != 1 {
			t.Fatal("not retried after the peer list came back")
		}
	})
}

// ---- 备签名闸自动接受 ----

func TestStandbyAcceptsOnlyTrustedGenerators(t *testing.T) {
	ctx := context.Background()
	newStandby := func(t *testing.T, opts harnessOptions) (*harness, peerMachine, recoveryKeyPair) {
		opts.role = records.RoleStandby
		h := newHarness(t, opts)
		primary := newPeerMachine(t, "amos-signer-main", "mch_signerM0001")
		must(t, h.store.TrustPeer(primary.trust(records.TrustModeEnrollFirstTrust)))
		return h, primary, newRecoveryKeyPair(t, "platform-recovery")
	}
	accepted := func(t *testing.T, h *harness) {
		t.Helper()
		rep := h.lastReport()
		if rep.Decrypt != "ok" || !rep.Confirmed || rep.TrialSign != "ok" || rep.Error != nil {
			t.Fatalf("report: %+v; logs:\n%s", rep, h.logs.String())
		}
	}
	refused := func(t *testing.T, h *harness, reason string) {
		t.Helper()
		rep := h.lastReport()
		if rep.Decrypt != "ok" || rep.Confirmed || rep.Error == nil || !strings.Contains(*rep.Error, reason) {
			t.Fatalf("report: %+v, want an error containing %q", rep, reason)
		}
	}

	t.Run("trusted primary, first trust", func(t *testing.T) {
		h, p, r := newStandby(t, harnessOptions{noConfirm: true})
		g := generateFor(t, "kgr_standby00001", p.ed, h.keys.X25519PublicKey(), p.xPub(), mustPublic(t, r.priv.Bytes()))
		h.server.items = []map[string]any{h.generatedItem(g, "kgr_standby00001", p.name, p.id, p.edPub(), h.roots, 40)}
		h.useGeneratedKey(g)
		must(t, h.runner.RunChecks(ctx))
		accepted(t, h)
		conf, _, _ := h.store.ActiveConfirmation(testfixture.PackageName)
		if conf.Mode != records.ConfirmModePeerGenerated || conf.ConfirmedBy != "auto:peer-generated:amos-signer-main" || conf.GeneratorEd25519SHA256 != p.edSHA() ||
			conf.CertificateSHA256 != g.CertificateSHA256 || conf.FirstSignMaxVersionCode != 140 || conf.TargetSDK != 28 || !trustroots.Equal(conf.TrustRoots, h.roots) {
			t.Fatalf("confirmation: %+v", conf)
		}
		if len(h.runner.Ready()) != 1 {
			t.Fatal("the accepted key is not in the ready list")
		}
	})

	t.Run("trusted primary, keeps confirmed trust roots", func(t *testing.T) {
		h, p, _ := newStandby(t, harnessOptions{})
		old, _, _ := h.store.ActiveConfirmation(testfixture.PackageName)
		g := generateFor(t, "kgr_standby00002", p.ed, h.keys.X25519PublicKey(), p.xPub())
		h.server.items = []map[string]any{h.generatedItem(g, "kgr_standby00002", p.name, p.id, p.edPub(), h.roots, 40)}
		h.useGeneratedKey(g)
		must(t, h.runner.RunChecks(ctx))
		accepted(t, h)
		conf, _, _ := h.store.ActiveConfirmation(testfixture.PackageName)
		if conf.CertificateSHA256 != g.CertificateSHA256 || conf.TargetSDK != old.TargetSDK || conf.Mode != records.ConfirmModePeerGenerated {
			t.Fatalf("confirmation: %+v", conf)
		}
	})

	t.Run("forged generation signature", func(t *testing.T) {
		h, p, _ := newStandby(t, harnessOptions{noConfirm: true})
		_, forger, _ := ed25519.GenerateKey(rand.Reader)
		g := generateFor(t, "kgr_standby00003", forger, h.keys.X25519PublicKey())
		// 服务端声称生成者是受信的主签名闸，签名却是别人的
		h.server.items = []map[string]any{h.generatedItem(g, "kgr_standby00003", p.name, p.id, p.edPub(), h.roots, 40)}
		h.useGeneratedKey(g)
		must(t, h.runner.RunChecks(ctx))
		refused(t, h, "does not verify")
		if _, ok, _ := h.store.ActiveConfirmation(testfixture.PackageName); ok || len(h.runner.Ready()) != 0 {
			t.Fatal("a forged generation was accepted")
		}
	})

	t.Run("untrusted generator", func(t *testing.T) {
		h, _, _ := newStandby(t, harnessOptions{noConfirm: true})
		rogue := newPeerMachine(t, "rogue-signer", "mch_signerR0001")
		g := generateFor(t, "kgr_standby00004", rogue.ed, h.keys.X25519PublicKey(), rogue.xPub())
		h.server.items = []map[string]any{h.generatedItem(g, "kgr_standby00004", rogue.name, rogue.id, rogue.edPub(), h.roots, 40)}
		h.useGeneratedKey(g)
		must(t, h.runner.RunChecks(ctx))
		refused(t, h, "does not trust")
		if _, ok, _ := h.store.ActiveConfirmation(testfixture.PackageName); ok {
			t.Fatal("a keystore from an untrusted generator was accepted")
		}
	})

	t.Run("box swapped into a signed upload", func(t *testing.T) {
		h, p, _ := newStandby(t, harnessOptions{noConfirm: true})
		signed := generateFor(t, "kgr_standby00005", p.ed, h.keys.X25519PublicKey())
		other := generateFor(t, "kgr_standby00006", p.ed, h.keys.X25519PublicKey())
		item := h.generatedItem(signed, "kgr_standby00005", p.name, p.id, p.edPub(), h.roots, 40)
		otherBox, _ := other.Upload.BoxFor(h.keys.X25519SHA256())
		item["box"], item["certificateSha256"] = otherBox, other.CertificateSHA256
		h.server.items = []map[string]any{item}
		h.useGeneratedKey(other)
		must(t, h.runner.RunChecks(ctx))
		refused(t, h, "not the one covered")
	})

	t.Run("server omits the verification fields", func(t *testing.T) {
		h, p, _ := newStandby(t, harnessOptions{noConfirm: true})
		g := generateFor(t, "kgr_standby00007", p.ed, h.keys.X25519PublicKey())
		item := h.generatedItem(g, "kgr_standby00007", p.name, p.id, p.edPub(), h.roots, 40)
		delete(item, "upload")
		delete(item, "generationRequestId")
		h.server.items = []map[string]any{item}
		h.useGeneratedKey(g)
		must(t, h.runner.RunChecks(ctx))
		refused(t, h, "signer confirm")
	})

	t.Run("trust roots changed", func(t *testing.T) {
		h, p, _ := newStandby(t, harnessOptions{})
		g := generateFor(t, "kgr_standby00008", p.ed, h.keys.X25519PublicKey())
		roots := h.roots
		roots.Scheme = "attacker"
		h.server.items = []map[string]any{h.generatedItem(g, "kgr_standby00008", p.name, p.id, p.edPub(), roots, 40)}
		h.useGeneratedKey(g)
		must(t, h.runner.RunChecks(ctx))
		refused(t, h, GenerationTrustRootsChanged)
		if _, ok, _ := h.store.Confirmation(testfixture.PackageName, h.key.CertificateSHA256); !ok {
			t.Fatal("the confirmed certificate was replaced despite changed trust roots")
		}
	})

	t.Run("superseded certificate replayed", func(t *testing.T) {
		h, p, _ := newStandby(t, harnessOptions{noConfirm: true})
		first := generateFor(t, "kgr_standby00009", p.ed, h.keys.X25519PublicKey())
		second := generateFor(t, "kgr_standby00010", p.ed, h.keys.X25519PublicKey())
		for _, step := range []struct {
			g  GeneratedKeystore
			id string
		}{{first, "kgr_standby00009"}, {second, "kgr_standby00010"}} {
			h.server.items = []map[string]any{h.generatedItem(step.g, step.id, p.name, p.id, p.edPub(), h.roots, 40)}
			h.useGeneratedKey(step.g)
			must(t, h.runner.RunChecks(ctx))
			accepted(t, h)
		}
		h.server.items = []map[string]any{h.generatedItem(first, "kgr_standby00009", p.name, p.id, p.edPub(), h.roots, 40)}
		h.useGeneratedKey(first)
		must(t, h.runner.RunChecks(ctx))
		refused(t, h, "confirmed for this package before")
		if conf, _, _ := h.store.ActiveConfirmation(testfixture.PackageName); conf.CertificateSHA256 != second.CertificateSHA256 {
			t.Fatal("a replayed older generation replaced the current key")
		}
	})

	t.Run("revoked peer is no longer trusted", func(t *testing.T) {
		h, p, _ := newStandby(t, harnessOptions{noConfirm: true})
		must(t, h.store.RevokePeer(p.name, "ops", "primary rebuilt"))
		g := generateFor(t, "kgr_standby00011", p.ed, h.keys.X25519PublicKey())
		h.server.items = []map[string]any{h.generatedItem(g, "kgr_standby00011", p.name, p.id, p.edPub(), h.roots, 40)}
		h.useGeneratedKey(g)
		must(t, h.runner.RunChecks(ctx))
		refused(t, h, "does not trust")
	})
}

// 主签名闸交回成功、写本机确认之前崩溃：重启后按本机签过的生成签名自动确认。
func TestPrimaryConfirmsItsOwnGenerationAfterACrash(t *testing.T) {
	h := newHarness(t, harnessOptions{noConfirm: true})
	g := generateFor(t, "kgr_crash0000001", h.keys.Ed25519, h.keys.X25519PublicKey())
	h.server.items = []map[string]any{h.generatedItem(g, "kgr_crash0000001", "server-says-anything", "mch_signerA0001", h.keys.Ed25519PublicKey(), h.roots, 12)}
	h.useGeneratedKey(g)
	must(t, h.runner.RunChecks(context.Background()))
	rep := h.lastReport()
	conf, _, _ := h.store.ActiveConfirmation(testfixture.PackageName)
	if !rep.Confirmed || rep.TrialSign != "ok" || conf.Mode != records.ConfirmModeFirstGeneration || conf.GeneratorName != testMachine || conf.FirstSignMaxVersionCode != 112 {
		t.Fatalf("report %+v confirmation %+v", rep, conf)
	}
}

// 手工流程写的本机记录（上线前的代码生成）：新代码照常启动、上报信任、处理生成请求。
func TestLegacyStateWorksWithTheNewCode(t *testing.T) {
	src := filepath.Join("..", "..", "records", "testdata", "legacy-2026-09-16")
	dir := t.TempDir()
	must(t, os.Chmod(dir, 0o700))
	for _, name := range []string{x25519KeyFile, ed25519KeyFile, records.TrustFileName, records.SignedFileName} {
		raw, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatal(err)
		}
		must(t, os.WriteFile(filepath.Join(dir, name), raw, 0o600))
	}
	if _, created, err := InitState(dir, "amos-signer-a"); err != nil || created {
		t.Fatalf("InitState on legacy records: %v %v", created, err)
	}
	keys, store, err := OpenRecords(dir, "amos-signer-a")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	trust, err := LocalTrust(keys, store)
	if err != nil || len(trust.Signers) != 1 || len(trust.Builders) != 1 || len(trust.RecoveryKeys) != 0 {
		t.Fatalf("LocalTrust on legacy records: %+v %v", trust, err)
	}
	var list strings.Builder
	if err := List(&list, keys, store); err != nil || !strings.Contains(list.String(), "mch_builderLEGACY0001") || !strings.Contains(list.String(), "trusted signing gates (0,") {
		t.Fatalf("List: %v\n%s", err, list.String())
	}
	// 迁移：信任恢复公钥之后，主签名闸（legacy 记录里是 primary）为已确认的包名换密钥
	h := newHarness(t, harnessOptions{})
	r := newRecoveryKeyPair(t, "platform-recovery")
	must(t, store.TrustRecovery(r.trust()))
	h.server.peers = PeersResponse{RecoveryKeys: []PeerRecoveryKey{r.view}}
	old, _, _ := store.ActiveConfirmation(testfixture.PackageName)
	item := generationItem("kgr_legacy000001", old.TrustRoots, 101)
	h.server.items = []map[string]any{item}
	runner := &Runner{Config: h.cfg, Keys: keys, Store: store, API: h.runner.API, Checker: pipeChecker{}, Signer: h.signer, Log: slogTo(h.logs),
		PollInterval: time.Millisecond, ChecksInterval: time.Hour, RetryDelays: []time.Duration{time.Millisecond}, KeyBits: 2048}
	must(t, runner.RunChecks(context.Background()))
	conf, _, _ := store.ActiveConfirmation(testfixture.PackageName)
	if len(h.server.failures) != 0 || conf.Mode != records.ConfirmModeRegenerated || conf.TargetSDK != old.TargetSDK || conf.FirstSignMaxVersionCode != 201 {
		t.Fatalf("failures %+v confirmation %+v; logs:\n%s", h.server.failures, conf, h.logs.String())
	}
}

func TestGenerateKeystoreRejectsBadInput(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	good := newPeerMachine(t, "x-signer", "mch_x0001").xPub()
	base := GenerateParams{RequestID: "kgr_bad000000001", TenantSlug: "AnyFun", PackageName: "com.anyfun.foundation", KeyAlias: testAlias,
		Recipients: [][]byte{good}, Generator: ed, KeyBits: 2048, Now: time.Now()}
	for name, mutate := range map[string]func(*GenerateParams){
		"request id":          func(p *GenerateParams) { p.RequestID = "../x" },
		"tenant":              func(p *GenerateParams) { p.TenantSlug = "any fun" },
		"package":             func(p *GenerateParams) { p.PackageName = "Com.Anyfun" },
		"alias":               func(p *GenerateParams) { p.KeyAlias = "a b" },
		"no recipients":       func(p *GenerateParams) { p.Recipients = nil },
		"duplicate recipient": func(p *GenerateParams) { p.Recipients = [][]byte{good, good} },
		"short recipient":     func(p *GenerateParams) { p.Recipients = [][]byte{good[:31]} },
		"generator":           func(p *GenerateParams) { p.Generator = ed[:32] },
	} {
		p := base
		mutate(&p)
		if _, err := GenerateKeystore(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
