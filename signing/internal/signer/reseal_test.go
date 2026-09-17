package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

// 同证书重新封装（第二轮约定第 5 节）。服务端是假的、由测试按脚本扮演，负面为主；节奏用注入的时钟表达，
// 不依赖机器快慢。

// selfView 是服务端视图里这台签名闸自己。
func (h *harness) selfView(id, role string) PeerSigner {
	r := role
	return PeerSigner{MachineID: id, Name: h.cfg.Name, Status: "active", SignerRole: &r,
		X25519PublicKey: base64.StdEncoding.EncodeToString(h.keys.X25519PublicKey()), X25519PublicKeySHA256: h.keys.X25519SHA256(),
		Ed25519PublicKey: base64.StdEncoding.EncodeToString(h.keys.Ed25519PublicKey()), Ed25519PublicKeySHA256: h.keys.Ed25519SHA256()}
}

// peerTrust 是别的签名闸在本机 trust-peer 这一台时写下的记录。
func (h *harness) peerTrust() records.PeerTrust {
	return records.PeerTrust{Name: h.cfg.Name, X25519PublicKeySHA256: h.keys.X25519SHA256(), Ed25519PublicKeySHA256: h.keys.Ed25519SHA256(),
		Mode: records.TrustModeOperator, Operator: "ops-alice"}
}

// sealerRef 是服务端记录的生成者或重新封装者。
type sealerRef struct {
	name, id string
	pub      ed25519.PublicKey
}

// keystoreItem 是服务端给 h 的租户项：当前密钥 k 里发给 h 的 box、全部收件人、版本。sealer 非 nil 时带上生成者
// 字段与签名；kind 是 sealKind 的值，kind 为 absent 时不带这个键（自动化第一轮的服务端）。
func (h *harness) keystoreItem(k GeneratedKeystore, version int, sealID string, sealer *sealerRef, kind any) map[string]any {
	h.t.Helper()
	box, ok := k.Upload.BoxFor(h.keys.X25519SHA256())
	if !ok {
		h.t.Fatal("the keystore is not sealed to this signing gate")
	}
	digest, _ := trustroots.Digest(h.roots)
	item := map[string]any{
		"tenantSlug": k.Upload.TenantSlug, "keystoreVersion": version, "packageName": k.Upload.PackageName, "certificateSha256": k.CertificateSHA256,
		"keyAlias": k.Upload.KeyAlias, "box": box, "trustRoots": h.roots, "trustRootsDigest": digest, "generationRequest": nil,
		"generator": nil, "generationSignature": nil, "generationRequestId": nil, "upload": nil, "sealKind": nil, "recipients": recipientsOf(k.Upload),
	}
	if sealer != nil {
		item["generator"] = map[string]any{"machineId": sealer.id, "name": sealer.name, "ed25519PublicKey": base64.StdEncoding.EncodeToString(sealer.pub),
			"ed25519PublicKeySha256": fingerprint.SHA256Hex(sealer.pub)}
		item["generationSignature"], item["generationRequestId"], item["upload"], item["sealKind"] = k.Signature, sealID, k.Upload, kind
	}
	if kind == absent {
		delete(item, "sealKind")
	}
	return item
}

// absent 标记"不带 sealKind 这个键"。
var absent = &struct{}{}

// sealPlaintext 把 plain（收件人与确认参数换掉）加密给 recipients，组成上传文件。
func sealPlaintext(t *testing.T, plain keystorebox.Plaintext, bound *keystorebox.Generation, recipients ...[]byte) keystorebox.Upload {
	t.Helper()
	shas := []string{}
	for _, pub := range recipients {
		shas = append(shas, fingerprint.SHA256Hex(pub))
	}
	sort.Strings(shas)
	plain.Recipients, plain.Generation = shas, bound
	upload := keystorebox.Upload{Format: keystorebox.UploadFormat, TenantSlug: plain.TenantSlug, PackageName: plain.PackageName, KeyAlias: plain.KeyAlias,
		CertificateSHA256: plain.CertificateSHA256, CreatedAt: plain.CreatedAt}
	for _, pub := range recipients {
		box, err := keystorebox.Seal(plain, pub)
		if err != nil {
			t.Fatal(err)
		}
		upload.Boxes = append(upload.Boxes, box)
	}
	return upload
}

// resealWorld：主签名闸 A、已有的备 B、新加的备 C（本机没有任何确认）、恢复公钥。A 本机 trust-peer 了 B 与 C、
// 信任恢复公钥；C 本机 trust-peer 了 A。当前密钥发给 A、B 与恢复公钥（离线导入的只发给 A、B），服务端的收件人
// 里没有 C。
type resealWorld struct {
	t        *testing.T
	a        *harness
	b        peerMachine
	c        *harness
	recovery recoveryKeyPair
	current  GeneratedKeystore
	plain    keystorebox.Plaintext // A 解开的当前明文
	aSealer  *sealerRef
	sealID   string
	kind     any
	version  int
}

func newResealWorld(t *testing.T, generated bool) *resealWorld {
	t.Helper()
	w := &resealWorld{
		t:        t,
		a:        newHarness(t, harnessOptions{noConfirm: generated}),
		b:        newPeerMachine(t, "amos-signer-b", "mch_signerB0001"),
		c:        newHarness(t, harnessOptions{name: "amos-signer-c", role: records.RoleStandby, noConfirm: true}),
		recovery: newRecoveryKeyPair(t, "platform-recovery"),
		version:  7,
	}
	w.aSealer = &sealerRef{name: testMachine, id: "mch_signerA0001", pub: w.a.keys.Ed25519PublicKey()}
	must(t, w.a.store.TrustPeer(w.b.trust(records.TrustModeOperator)))
	must(t, w.a.store.TrustPeer(w.c.peerTrust()))
	must(t, w.a.store.TrustRecovery(w.recovery.trust()))
	must(t, w.c.store.TrustPeer(w.a.peerTrust()))
	w.a.server.peers = PeersResponse{
		Signers:      []PeerSigner{w.a.selfView("mch_signerA0001", "primary"), w.b.view("standby"), w.c.selfView("mch_signerC0001", "standby")},
		RecoveryKeys: []PeerRecoveryKey{w.recovery.view},
	}
	if generated {
		w.sealID, w.kind = "kgr_world0000001", "generation"
		w.current = generateFor(t, w.sealID, w.a.keys.Ed25519, binding(w.a.digest, 140, ""), w.a.keys.X25519PublicKey(), w.b.xPub(), mustPublic(t, w.recovery.priv.Bytes()))
		// A 按本机签过的生成自动确认（与交回后写确认是同一个结果）；这一项还没有收件人列表，不会重新封装
		w.a.server.items = []map[string]any{w.a.generatedItem(w.current, w.sealID, testMachine, "mch_signerA0001", w.a.keys.Ed25519PublicKey(), w.a.roots)}
		w.a.useGeneratedKey(w.current)
		must(t, w.a.runner.RunChecks(context.Background()))
		if conf, ok, _ := w.a.store.Confirmation(testfixture.PackageName, w.current.CertificateSHA256); !ok || conf.Mode != records.ConfirmModeFirstGeneration {
			t.Fatalf("the primary did not confirm its own generation: %+v; logs:\n%s", conf, w.a.logs.String())
		}
	} else {
		// 离线导入：明文没有 generation，只加密给 A、B；A 本机是运维 confirm 的
		base := keystorebox.Plaintext{Purpose: keystorebox.Purpose, TenantSlug: testfixture.TenantSlug, PackageName: testfixture.PackageName,
			CertificateSHA256: w.a.key.CertificateSHA256, KeyAlias: testAlias, CreatedAt: "2026-09-16T00:00:00Z",
			P12Base64: base64.StdEncoding.EncodeToString(w.a.key.PKCS12), StorePassword: w.a.key.Password, KeyPassword: w.a.key.Password}
		w.current = GeneratedKeystore{Upload: sealPlaintext(t, base, nil, w.a.keys.X25519PublicKey(), w.b.xPub()), CertificateSHA256: w.a.key.CertificateSHA256}
	}
	box, _ := w.current.Upload.BoxFor(w.a.keys.X25519SHA256())
	plain, err := keystorebox.Open(box, w.a.keys.X25519.Bytes())
	must(t, err)
	w.plain = plain
	w.serveA(nil)
	return w
}

// serveA 让服务端给 A 当前密钥；recipients 非 nil 时服务端报的收件人换成它（模拟服务端乱报）。
func (w *resealWorld) serveA(recipients []string) {
	w.t.Helper()
	var sealer *sealerRef
	if w.kind != nil {
		sealer = w.aSealer
	}
	item := w.a.keystoreItem(w.current, w.version, w.sealID, sealer, w.kind)
	if recipients != nil {
		item["recipients"] = recipients
	}
	w.a.server.mu.Lock()
	w.a.server.items = []map[string]any{item}
	w.a.server.mu.Unlock()
}

func (w *resealWorld) recipientsWith(extra ...string) []string {
	out := recipientsOf(w.current.Upload)
	out = append(out, extra...)
	sort.Strings(out)
	return out
}

func (w *resealWorld) submissions() []ResealSubmit {
	w.a.server.mu.Lock()
	defer w.a.server.mu.Unlock()
	return append([]ResealSubmit(nil), w.a.server.reseals...)
}

// resealed 是服务端落库后的重新封装结果。
func resealedKeystore(sub ResealSubmit) GeneratedKeystore {
	return GeneratedKeystore{Upload: sub.Upload, Signature: sub.Signature, CertificateSHA256: sub.Upload.CertificateSHA256}
}

// serveC 让服务端把重新封装的结果给 C（sealKind reseal，封装者 A）。
func (w *resealWorld) serveC(k GeneratedKeystore, sealID string, sealer *sealerRef, kind any, mutate func(map[string]any)) {
	w.t.Helper()
	item := w.c.keystoreItem(k, w.version+1, sealID, sealer, kind)
	if mutate != nil {
		mutate(item)
	}
	w.c.server.mu.Lock()
	w.c.server.items = []map[string]any{item}
	w.c.server.mu.Unlock()
	w.c.useGeneratedKey(k)
	must(w.t, w.c.runner.RunChecks(context.Background()))
}

func sortedSHAs(keys ...[]byte) []string {
	out := []string{}
	for _, k := range keys {
		out = append(out, fingerprint.SHA256Hex(k))
	}
	sort.Strings(out)
	return out
}

// ---- 正面 ----

// 主备各有密钥时新增备 C，互相 trust-peer：下一轮主签名闸把同一张证书重新封装给 C（明文除收件人与确认参数外逐项相同，
// 确认参数取主签名闸本机当前的确认），签重新封装签名交回；C 验签后按这份参数首次信任、试签通过；证书不变。
// 离线导入的密钥（明文没有 generation）同样可以，重新封装之后就有了。
func TestResealGivesANewStandbyTheExistingKey(t *testing.T) {
	for name, generated := range map[string]bool{"generated key": true, "imported key": false} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			w := newResealWorld(t, generated)
			aConf, _, _ := w.a.store.ActiveConfirmation(testfixture.PackageName)
			must(t, w.a.runner.RunChecks(ctx))
			subs := w.submissions()
			if len(subs) != 1 {
				t.Fatalf("reseals %d; logs:\n%s", len(subs), w.a.logs.String())
			}
			sub := subs[0]
			if !keystorebox.ValidResealID(sub.ResealID) || sub.TenantSlug != testfixture.TenantSlug || sub.KeystoreVersion != int64(w.version) {
				t.Fatalf("submission: %+v", sub)
			}
			if err := keystorebox.VerifyReseal(w.a.keys.Ed25519PublicKey(), sub.ResealID, sub.Upload, sub.Signature); err != nil {
				t.Fatalf("reseal signature: %v", err)
			}
			if err := keystorebox.VerifyGeneration(w.a.keys.Ed25519PublicKey(), sub.ResealID, sub.Upload, sub.Signature); err == nil {
				t.Fatal("the reseal signature also verifies as a generation signature")
			}
			u := sub.Upload
			if u.CertificateSHA256 != w.current.CertificateSHA256 || u.PackageName != testfixture.PackageName || u.KeyAlias != w.plain.KeyAlias || u.CreatedAt != w.plain.CreatedAt {
				t.Fatalf("upload outer fields: %+v", u)
			}
			want := sortedSHAs(w.a.keys.X25519PublicKey(), w.b.xPub(), w.c.keys.X25519PublicKey(), mustPublic(t, w.recovery.priv.Bytes()))
			if got := recipientsOf(u); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("recipients %v, want %v", got, want)
			}
			wantBinding := keystorebox.Generation{TrustRootsDigest: aConf.TrustRootsDigest, MinSDK: aConf.MinSDK, TargetSDK: aConf.TargetSDK,
				FirstSignMaxVersionCode: aConf.FirstSignMaxVersionCode, SupersedesCertificateSHA256: w.current.CertificateSHA256, Kind: keystorebox.GenerationKindReseal}
			for who, key := range map[string][]byte{"C": w.c.keys.X25519.Bytes(), "B": w.b.x.Bytes(), "recovery": w.recovery.priv.Bytes()} {
				box, _ := u.BoxFor(fingerprint.SHA256Hex(mustPublic(t, key)))
				plain, err := keystorebox.Open(box, key)
				if err != nil || plain.P12Base64 != w.plain.P12Base64 || plain.StorePassword != w.plain.StorePassword || plain.CertificateSHA256 != w.plain.CertificateSHA256 ||
					plain.CreatedAt != w.plain.CreatedAt || strings.Join(plain.Recipients, ",") != strings.Join(want, ",") {
					t.Fatalf("%s cannot open the same key from its box: %v", who, err)
				}
				if plain.Generation == nil || *plain.Generation != wantBinding {
					t.Fatalf("%s box binding %+v, want %+v", who, plain.Generation, wantBinding)
				}
			}
			if after, _, _ := w.a.store.ActiveConfirmation(testfixture.PackageName); after.ConfirmedAt != aConf.ConfirmedAt || after.CertificateSHA256 != aConf.CertificateSHA256 {
				t.Fatalf("resealing changed the primary's confirmation: %+v", after)
			}
			w.a.runner.mu.Lock()
			due := w.a.runner.checksDue
			w.a.runner.mu.Unlock()
			if !due {
				t.Fatal("the primary does not re-check right after resealing")
			}

			// 服务端落库：C 本机没有任何确认，验证封装者是本机信任的 A、重新封装签名有效、参数是重新封装，首次信任
			k := resealedKeystore(sub)
			w.serveC(k, sub.ResealID, w.aSealer, "reseal", nil)
			rep := w.c.lastReport()
			if rep.Decrypt != "ok" || !rep.Confirmed || rep.TrialSign != "ok" || rep.Error != nil {
				t.Fatalf("new standby report: %+v; logs:\n%s", rep, w.c.logs.String())
			}
			conf, ok, _ := w.c.store.ActiveConfirmation(testfixture.PackageName)
			if !ok || conf.Mode != records.ConfirmModePeerResealed || conf.ConfirmedBy != "auto:peer-resealed:"+testMachine || conf.CertificateSHA256 != w.current.CertificateSHA256 ||
				conf.GenerationRequestID != sub.ResealID || conf.GeneratorEd25519SHA256 != w.a.keys.Ed25519SHA256() || conf.TrustRootsDigest != aConf.TrustRootsDigest ||
				conf.MinSDK != aConf.MinSDK || conf.TargetSDK != aConf.TargetSDK || conf.FirstSignMaxVersionCode != aConf.FirstSignMaxVersionCode ||
				!trustroots.Equal(conf.TrustRoots, w.c.roots) {
				t.Fatalf("new standby confirmation: %+v (primary %+v)", conf, aConf)
			}
			if ready := w.c.runner.Ready(); len(ready) != 1 || ready[0].CertificateSHA256 != w.current.CertificateSHA256 {
				t.Fatalf("new standby ready: %+v", ready)
			}

			// A 拿到落库后的记录（它自己重新封装的）：收件人齐了，不再重新封装；照常确认、试签、就绪
			w.version++
			w.current, w.sealID, w.kind = k, sub.ResealID, "reseal"
			w.serveA(nil)
			must(t, w.a.runner.RunChecks(ctx))
			if len(w.submissions()) != 1 {
				t.Fatalf("resealed again although nothing is missing: %d", len(w.submissions()))
			}
			if rep := w.a.lastReport(); !rep.Confirmed || rep.TrialSign != "ok" || rep.Error != nil || len(w.a.runner.Ready()) != 1 {
				t.Fatalf("primary after the reseal: %+v ready %+v", rep, w.a.runner.Ready())
			}
		})
	}
}

// ---- 服务端多报、换公钥 ----

func TestResealUsesOnlyLocallyTrustedRecipients(t *testing.T) {
	ctx := context.Background()
	rogue := func(t *testing.T) (PeerSigner, recoveryKeyPair) {
		return newPeerMachine(t, "rogue-signer", "mch_signerR0001").view("standby"), newRecoveryKeyPair(t, "rogue-recovery")
	}
	t.Run("extra active signer and unpinned recovery key do not trigger", func(t *testing.T) {
		w := newResealWorld(t, true)
		signer, key := rogue(t)
		w.a.server.peers.Signers = append(w.a.server.peers.Signers, signer)
		w.a.server.peers.RecoveryKeys = append(w.a.server.peers.RecoveryKeys, key.view)
		// C 已经在收件人里：本机信任的都在，服务端多报的两个不算缺
		w.serveA(w.recipientsWith(w.c.keys.X25519SHA256()))
		must(t, w.a.runner.RunChecks(ctx))
		if n := len(w.submissions()); n != 0 {
			t.Fatalf("resealed for recipients the primary does not trust: %d", n)
		}
	})
	t.Run("extra active signer and unpinned recovery key are not added", func(t *testing.T) {
		w := newResealWorld(t, true)
		signer, key := rogue(t)
		w.a.server.peers.Signers = append(w.a.server.peers.Signers, signer)
		w.a.server.peers.RecoveryKeys = append(w.a.server.peers.RecoveryKeys, key.view)
		must(t, w.a.runner.RunChecks(ctx))
		subs := w.submissions()
		want := sortedSHAs(w.a.keys.X25519PublicKey(), w.b.xPub(), w.c.keys.X25519PublicKey(), mustPublic(t, w.recovery.priv.Bytes()))
		if len(subs) != 1 || strings.Join(recipientsOf(subs[0].Upload), ",") != strings.Join(want, ",") {
			t.Fatalf("reseals %+v, want exactly %v (not %s, %s)", subs, want, signer.X25519PublicKeySHA256, key.view.X25519PublicKeySHA256)
		}
	})
	swaps := map[string]func(t *testing.T, w *resealWorld) PeerSigner{
		// 服务端把 C 的登记换成攻击者的公钥（指纹与公钥自洽，但不是本机 trust-peer 的值）
		"server swaps the trusted signer's keys": func(t *testing.T, w *resealWorld) PeerSigner {
			attacker := newPeerMachine(t, w.c.cfg.Name, "mch_signerC0001").view("standby")
			return attacker
		},
		// 指纹照抄本机信任的，公钥换成攻击者的
		"server keeps the fingerprint but swaps the public key": func(t *testing.T, w *resealWorld) PeerSigner {
			view := w.c.selfView("mch_signerC0001", "standby")
			view.X25519PublicKey = newPeerMachine(t, "x", "mch_x0001").view("standby").X25519PublicKey
			return view
		},
		"trusted signer is not active on the server": func(t *testing.T, w *resealWorld) PeerSigner {
			view := w.c.selfView("mch_signerC0001", "standby")
			view.Status = "pending_key"
			return view
		},
	}
	for name, swap := range swaps {
		t.Run(name, func(t *testing.T) {
			w := newResealWorld(t, true)
			w.a.server.peers.Signers[2] = swap(t, w)
			must(t, w.a.runner.RunChecks(ctx))
			if n := len(w.submissions()); n != 0 {
				t.Fatalf("resealed to a key the primary does not trust: %d; logs:\n%s", n, w.a.logs.String())
			}
		})
	}
}

// ---- 信任根 ----

func TestResealFollowsTheConfirmedTrustRoots(t *testing.T) {
	ctx := context.Background()
	attacker := func(h *harness) trustroots.Roots {
		roots := h.roots
		roots.APIBaseURL, roots.AppLinksHosts = "https://api.attacker.example", []string{"api.attacker.example"}
		roots, err := roots.Normalize()
		must(h.t, err)
		return roots
	}
	t.Run("primary does not reseal while the server's trust roots differ", func(t *testing.T) {
		w := newResealWorld(t, true)
		w.serveA(nil)
		roots := attacker(w.a)
		digest, _ := trustroots.Digest(roots)
		w.a.server.items[0]["trustRoots"], w.a.server.items[0]["trustRootsDigest"] = roots, digest
		must(t, w.a.runner.RunChecks(ctx))
		if n := len(w.submissions()); n != 0 {
			t.Fatalf("resealed while the trust roots changed: %d", n)
		}
	})
	for name, mutate := range map[string]func(w *resealWorld, item map[string]any){
		"server swaps the trust roots": func(w *resealWorld, item map[string]any) {
			roots := attacker(w.c)
			digest, _ := trustroots.Digest(roots)
			item["trustRoots"], item["trustRootsDigest"] = roots, digest
		},
		"server digest does not match the roots": func(w *resealWorld, item map[string]any) {
			item["trustRootsDigest"] = strings.Repeat("ab", 32)
		},
		"server sends no trust roots": func(w *resealWorld, item map[string]any) {
			item["trustRoots"], item["trustRootsDigest"] = nil, nil
		},
	} {
		t.Run("new standby, "+name, func(t *testing.T) {
			w := newResealWorld(t, true)
			must(t, w.a.runner.RunChecks(ctx))
			sub := w.submissions()[0]
			w.serveC(resealedKeystore(sub), sub.ResealID, w.aSealer, "reseal", func(item map[string]any) { mutate(w, item) })
			rep := w.c.lastReport()
			if rep.Confirmed || rep.Error == nil {
				t.Fatalf("report: %+v; logs:\n%s", rep, w.c.logs.String())
			}
			if _, ok, _ := w.c.store.ActiveConfirmation(testfixture.PackageName); ok {
				t.Fatal("the new standby trusted trust roots the resealer did not confirm")
			}
		})
	}
}

// ---- 备签名闸拒收 ----

func TestStandbyRefusesResealsItCannotVerify(t *testing.T) {
	ctx := context.Background()
	cases := map[string]func(t *testing.T, w *resealWorld, sub ResealSubmit) (GeneratedKeystore, string, *sealerRef, any, string){
		"resealer is not trusted locally": func(t *testing.T, w *resealWorld, sub ResealSubmit) (GeneratedKeystore, string, *sealerRef, any, string) {
			must(t, w.c.store.RevokePeer(testMachine, "ops", "not trusted in this test"))
			return resealedKeystore(sub), sub.ResealID, w.aSealer, "reseal", "does not trust"
		},
		"server names a trusted resealer but another key signed": func(t *testing.T, w *resealWorld, sub ResealSubmit) (GeneratedKeystore, string, *sealerRef, any, string) {
			_, forger, _ := ed25519.GenerateKey(rand.Reader)
			k := resealedKeystore(sub)
			k.Signature, _ = keystorebox.SignReseal(forger, sub.ResealID, sub.Upload)
			return k, sub.ResealID, w.aSealer, "reseal", "does not verify"
		},
		// 跨域重放：主签名闸对同一个 id 与上传文件签的是生成签名
		"generation signature presented as a reseal": func(t *testing.T, w *resealWorld, sub ResealSubmit) (GeneratedKeystore, string, *sealerRef, any, string) {
			k := resealedKeystore(sub)
			k.Signature, _ = keystorebox.SignGeneration(w.a.keys.Ed25519, sub.ResealID, sub.Upload)
			return k, sub.ResealID, w.aSealer, "reseal", "does not verify"
		},
		"reseal presented as a generation": func(t *testing.T, w *resealWorld, sub ResealSubmit) (GeneratedKeystore, string, *sealerRef, any, string) {
			return resealedKeystore(sub), sub.ResealID, w.aSealer, "generation", "does not verify"
		},
		"reseal presented without a sealKind": func(t *testing.T, w *resealWorld, sub ResealSubmit) (GeneratedKeystore, string, *sealerRef, any, string) {
			return resealedKeystore(sub), sub.ResealID, w.aSealer, absent, "does not verify"
		},
		// 明文是重新封装的参数，签名却是生成签名、按生成下发：签名对得上，明文的 Kind 对不上
		"reseal plaintext signed and sent as a generation": func(t *testing.T, w *resealWorld, sub ResealSubmit) (GeneratedKeystore, string, *sealerRef, any, string) {
			k := resealedKeystore(sub)
			k.Signature, _ = keystorebox.SignGeneration(w.a.keys.Ed25519, "kgr_crossdomain0001", sub.Upload)
			return k, "kgr_crossdomain0001", w.aSealer, "generation", "parameters are a reseal"
		},
		"generation plaintext signed and sent as a reseal": func(t *testing.T, w *resealWorld, sub ResealSubmit) (GeneratedKeystore, string, *sealerRef, any, string) {
			bound := binding(w.a.digest, 140, "")
			u := sealPlaintext(t, w.plain, bound, w.c.keys.X25519PublicKey())
			sig, _ := keystorebox.SignReseal(w.a.keys.Ed25519, sub.ResealID, u)
			return GeneratedKeystore{Upload: u, Signature: sig, CertificateSHA256: u.CertificateSHA256}, sub.ResealID, w.aSealer, "reseal", "not a reseal"
		},
		"reseal id without the rsl_ prefix": func(t *testing.T, w *resealWorld, sub ResealSubmit) (GeneratedKeystore, string, *sealerRef, any, string) {
			return resealedKeystore(sub), "kgr_" + strings.TrimPrefix(sub.ResealID, "rsl_"), w.aSealer, "reseal", "does not verify"
		},
		"unknown sealKind": func(t *testing.T, w *resealWorld, sub ResealSubmit) (GeneratedKeystore, string, *sealerRef, any, string) {
			return resealedKeystore(sub), sub.ResealID, w.aSealer, "rotation", "unknown sealKind"
		},
		// 本机对这个包名确认的是另一张证书：重新封装换不了证书
		"another certificate is confirmed locally": func(t *testing.T, w *resealWorld, sub ResealSubmit) (GeneratedKeystore, string, *sealerRef, any, string) {
			must(t, w.c.store.Confirm(records.Confirmation{TenantSlug: testfixture.TenantSlug, PackageName: testfixture.PackageName, CertificateSHA256: strings.Repeat("ef", 32),
				KeyAlias: testAlias, KeystoreVersion: 1, TrustRoots: w.c.roots, TrustRootsDigest: w.c.digest, MinSDK: 24, TargetSDK: 28, FirstSignMaxVersionCode: 50, ConfirmedBy: "ops"}))
			return resealedKeystore(sub), sub.ResealID, w.aSealer, "reseal", "keeps the certificate"
		},
		// 评审 P2-1：租户在本机确认过别的包名，不按首次信任接受
		"tenant confirmed locally for another package": func(t *testing.T, w *resealWorld, sub ResealSubmit) (GeneratedKeystore, string, *sealerRef, any, string) {
			must(t, w.c.store.Confirm(records.Confirmation{TenantSlug: testfixture.TenantSlug, PackageName: "com.anyfun.other", CertificateSHA256: strings.Repeat("ef", 32),
				KeyAlias: testAlias, KeystoreVersion: 1, TrustRoots: w.c.roots, TrustRootsDigest: w.c.digest, MinSDK: 24, TargetSDK: 28, FirstSignMaxVersionCode: 50, ConfirmedBy: "ops"}))
			return resealedKeystore(sub), sub.ResealID, w.aSealer, "reseal", GenerationTrustRootsChanged
		},
		// 服务端说是本机自己重新封装的，本机却没有这张证书的确认
		"self-resealed without a local confirmation": func(t *testing.T, w *resealWorld, sub ResealSubmit) (GeneratedKeystore, string, *sealerRef, any, string) {
			u := sealPlaintext(t, w.plain, &keystorebox.Generation{TrustRootsDigest: w.c.digest, MinSDK: 24, TargetSDK: 28, FirstSignMaxVersionCode: 140,
				SupersedesCertificateSHA256: w.plain.CertificateSHA256, Kind: keystorebox.GenerationKindReseal}, w.c.keys.X25519PublicKey())
			sig, _ := keystorebox.SignReseal(w.c.keys.Ed25519, sub.ResealID, u)
			self := &sealerRef{name: w.c.cfg.Name, id: "mch_signerC0001", pub: w.c.keys.Ed25519PublicKey()}
			return GeneratedKeystore{Upload: u, Signature: sig, CertificateSHA256: u.CertificateSHA256}, sub.ResealID, self, "reseal", "resealed this keystore itself"
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w := newResealWorld(t, true)
			must(t, w.a.runner.RunChecks(ctx))
			subs := w.submissions()
			if len(subs) != 1 {
				t.Fatalf("no reseal to deliver: %d", len(subs))
			}
			k, sealID, sealer, kind, reason := tc(t, w, subs[0])
			before, hadBefore, _ := w.c.store.ActiveConfirmation(testfixture.PackageName)
			w.serveC(k, sealID, sealer, kind, nil)
			rep := w.c.lastReport()
			if rep.Decrypt != "ok" || rep.Confirmed || rep.Error == nil || !strings.Contains(*rep.Error, reason) {
				t.Fatalf("report %+v, want an error containing %q; logs:\n%s", rep, reason, w.c.logs.String())
			}
			after, has, _ := w.c.store.ActiveConfirmation(testfixture.PackageName)
			if has != hadBefore || after.CertificateSHA256 != before.CertificateSHA256 || after.ConfirmedAt != before.ConfirmedAt {
				t.Fatalf("a refused reseal changed the local confirmation: %+v -> %+v", before, after)
			}
			if len(w.c.runner.Ready()) != 0 {
				t.Fatal("a refused reseal is ready for signing")
			}
		})
	}
}

// 评审 P2-3 的规则同样适用：本机是主时，别的签名闸（即使本机信任它）重新封装的密钥一律不接受。
func TestLocalPrimaryRefusesResealsByOthers(t *testing.T) {
	w := newResealWorld(t, true)
	must(t, w.a.runner.RunChecks(context.Background()))
	sub := w.submissions()[0]
	// 另一台自认为是主的签名闸 D 信任 A；A 的重新封装发给 D（D 本机没有确认）
	d := newHarness(t, harnessOptions{name: "amos-signer-d", noConfirm: true})
	must(t, d.store.TrustPeer(w.a.peerTrust()))
	u := sealPlaintext(t, w.plain, &keystorebox.Generation{TrustRootsDigest: d.digest, MinSDK: 24, TargetSDK: 28, FirstSignMaxVersionCode: 140,
		SupersedesCertificateSHA256: w.plain.CertificateSHA256, Kind: keystorebox.GenerationKindReseal}, d.keys.X25519PublicKey())
	sig, _ := keystorebox.SignReseal(w.a.keys.Ed25519, sub.ResealID, u)
	k := GeneratedKeystore{Upload: u, Signature: sig, CertificateSHA256: u.CertificateSHA256}
	d.server.items = []map[string]any{d.keystoreItem(k, 8, sub.ResealID, w.aSealer, "reseal")}
	d.useGeneratedKey(k)
	must(t, d.runner.RunChecks(context.Background()))
	rep := d.lastReport()
	if rep.Confirmed || rep.Error == nil || !strings.Contains(*rep.Error, "only accepts keystores it generated itself") {
		t.Fatalf("report: %+v; logs:\n%s", rep, d.logs.String())
	}
	if _, ok, _ := d.store.ActiveConfirmation(testfixture.PackageName); ok {
		t.Fatal("a local primary confirmed a key resealed by another signing gate")
	}
}

// ---- 节奏：收件人抖动、服务端拒收之后 ----

func TestResealAttemptsAreThrottledPerTenant(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	setup := func(t *testing.T) (*resealWorld, *time.Time) {
		w := newResealWorld(t, true)
		now := start
		w.a.runner.Now = func() time.Time { return now }
		return w, &now
	}
	round := func(t *testing.T, w *resealWorld, now *time.Time, advance time.Duration, recipients []string) int {
		t.Helper()
		*now = now.Add(advance)
		w.serveA(recipients)
		must(t, w.a.runner.RunChecks(ctx))
		return len(w.submissions())
	}
	t.Run("recipients flap every round", func(t *testing.T) {
		w, now := setup(t)
		// 服务端每轮报的收件人都缺一个（这轮缺 C，下轮缺 B……）：10 分钟内只尝试一次
		missingB := sortedSHAs(w.a.keys.X25519PublicKey(), w.c.keys.X25519PublicKey(), mustPublic(t, w.recovery.priv.Bytes()))
		if n := round(t, w, now, 0, nil); n != 1 {
			t.Fatalf("first round: %d", n)
		}
		if n := round(t, w, now, time.Minute, missingB); n != 1 {
			t.Fatalf("second round (1 minute): %d", n)
		}
		if n := round(t, w, now, 8*time.Minute+59*time.Second, nil); n != 1 {
			t.Fatalf("9m59s after the attempt: %d", n)
		}
		if n := round(t, w, now, time.Second, missingB); n != 2 {
			t.Fatalf("10 minutes after the attempt: %d", n)
		}
	})
	for name, tc := range map[string]struct {
		failure    problem
		nextRound  int // 一分钟后的下一轮总共交了几次
		firstCalls int
	}{
		"stale version is retried next round":           {problem{409, "KEYSTORE_RESEAL_STALE"}, 2, 1},
		"pending generation is retried next round":      {problem{409, "KEYSTORE_GENERATION_IN_PROGRESS"}, 2, 1},
		"refused upload waits for the 10-minute window": {problem{422, "KEYSTORE_RESEAL_MISMATCH"}, 1, 1},
		"rate limit is not retried in place":            {problem{429, "KEYSTORE_RESEAL_RATE_LIMITED"}, 1, 1},
		"server error is retried in place only":         {problem{503, "UNAVAILABLE"}, 3, 3},
	} {
		t.Run(name, func(t *testing.T) {
			w, now := setup(t)
			w.a.server.resealStatus = []problem{tc.failure, tc.failure, tc.failure}
			if n := round(t, w, now, 0, nil); n != tc.firstCalls {
				t.Fatalf("first round submitted %d times, want %d", n, tc.firstCalls)
			}
			if n := round(t, w, now, time.Minute, nil); n != tc.nextRound {
				t.Fatalf("after a minute: %d submissions, want %d", n, tc.nextRound)
			}
			if rep := w.a.lastReport(); !rep.Confirmed || rep.TrialSign != "ok" || len(w.a.runner.Ready()) != 1 {
				t.Fatalf("a failed reseal affected the primary's own check: %+v", rep)
			}
		})
	}
	t.Run("pending generation request on the item", func(t *testing.T) {
		w, now := setup(t)
		w.serveA(nil)
		// 生成照常处理（服务端说请求已过期，丢弃生成的密钥），这一项不重新封装：生成本来就会换收件人
		w.a.server.submitStatus["kgr_pending00001"] = problem{409, "KEYSTORE_GENERATION_STALE"}
		w.a.server.items[0]["generationRequest"] = generationItem("kgr_pending00001", w.a.roots, 5)["generationRequest"]
		*now = now.Add(time.Minute)
		must(t, w.a.runner.RunChecks(ctx))
		if n := len(w.submissions()); n != 0 {
			t.Fatalf("resealed while a generation is pending: %d", n)
		}
	})
}

// ---- 没有可用的恢复公钥 ----

func TestResealWithoutAUsableRecoveryKeyIsReported(t *testing.T) {
	ctx := context.Background()
	for name, setup := range map[string]func(w *resealWorld){
		"no recovery key trusted locally": func(w *resealWorld) {
			must(w.t, w.a.store.RevokeRecovery(w.recovery.view.X25519PublicKeySHA256, "ops", "rotated away in this test"))
		},
		"trusted recovery key revoked on the server": func(w *resealWorld) {
			w.a.server.peers.RecoveryKeys[0].Revoked = true
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newResealWorld(t, true)
			setup(w)
			must(t, w.a.runner.RunChecks(ctx))
			if n := len(w.submissions()); n != 0 {
				t.Fatalf("resealed without a recovery recipient: %d", n)
			}
			rep := w.a.lastReport()
			if !rep.Confirmed || rep.TrialSign != "ok" || rep.Error == nil || !strings.Contains(*rep.Error, GenerationRecoveryKeyNotPinned) {
				t.Fatalf("report: %+v", rep)
			}
			if len(w.a.runner.Ready()) != 1 {
				t.Fatal("a missing recovery key made the primary unready")
			}
		})
	}
}

// ---- promote 撤销旧主之后 ----

// 本机从备提升为主时自动撤销了旧主 P；服务端仍把 P 报成 active，当前收件人里也有 P。之后新加的签名闸触发重新封装，
// 新的收件人不再包含 P。
func TestResealAfterPromoteDropsTheRevokedPreviousPrimary(t *testing.T) {
	a := newHarness(t, harnessOptions{role: records.RoleStandby})
	p := newPeerMachine(t, "amos-signer-old", "mch_signerP0001")
	c := newPeerMachine(t, "amos-signer-c", "mch_signerC0001")
	r := newRecoveryKeyPair(t, "platform-recovery")
	must(t, a.store.TrustPeer(p.trust(records.TrustModeOperator)))
	must(t, a.store.TrustRecovery(r.trust()))
	revoked, err := a.store.Promote(records.RoleChange{Role: records.RolePrimary, Mode: records.RoleModeManual, PreviousPrimaryEd25519SHA256: p.edSHA(),
		Operator: "ops", Reason: "the old primary was lost"})
	if err != nil || len(revoked) != 1 || revoked[0] != p.name {
		t.Fatalf("promote: %v %v", revoked, err)
	}
	must(t, a.store.TrustPeer(c.trust(records.TrustModeOperator)))
	a.server.peers = PeersResponse{Signers: []PeerSigner{a.selfView("mch_signerA0001", "primary"), p.view("standby"), c.view("standby")},
		RecoveryKeys: []PeerRecoveryKey{r.view}}
	base := keystorebox.Plaintext{Purpose: keystorebox.Purpose, TenantSlug: testfixture.TenantSlug, PackageName: testfixture.PackageName,
		CertificateSHA256: a.key.CertificateSHA256, KeyAlias: testAlias, CreatedAt: "2026-09-16T00:00:00Z",
		P12Base64: base64.StdEncoding.EncodeToString(a.key.PKCS12), StorePassword: a.key.Password, KeyPassword: a.key.Password}
	k := GeneratedKeystore{Upload: sealPlaintext(t, base, nil, a.keys.X25519PublicKey(), p.xPub(), mustPublic(t, r.priv.Bytes())), CertificateSHA256: a.key.CertificateSHA256}
	a.server.items = []map[string]any{a.keystoreItem(k, 5, "", nil, nil)}
	must(t, a.runner.RunChecks(context.Background()))
	a.server.mu.Lock()
	reseals := append([]ResealSubmit(nil), a.server.reseals...)
	a.server.mu.Unlock()
	if len(reseals) != 1 {
		t.Fatalf("reseals: %d; logs:\n%s", len(reseals), a.logs.String())
	}
	want := sortedSHAs(a.keys.X25519PublicKey(), c.xPub(), mustPublic(t, r.priv.Bytes()))
	if got := recipientsOf(reseals[0].Upload); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("recipients %v, want %v (the revoked previous primary %s must be dropped)", got, want, p.xSHA())
	}
}

// ---- 旧记录 ----

// 自动化第一轮的服务端不下发 sealKind、明文没有 kind：按生成处理，与之前完全一样；服务端显式说 generation 也一样。
func TestItemsWithoutSealKindAreGenerations(t *testing.T) {
	for name, kind := range map[string]any{"no sealKind key": absent, "sealKind null": nil, "sealKind generation": "generation"} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, harnessOptions{role: records.RoleStandby, noConfirm: true})
			p := newPeerMachine(t, "amos-signer-main", "mch_signerM0001")
			must(t, h.store.TrustPeer(p.trust(records.TrustModeOperator)))
			g := generateFor(t, "kgr_legacy0000001", p.ed, binding(h.digest, 140, ""), h.keys.X25519PublicKey(), p.xPub())
			item := h.keystoreItem(g, 7, "kgr_legacy0000001", &sealerRef{name: p.name, id: p.id, pub: p.edPub()}, kind)
			h.server.items = []map[string]any{item}
			h.useGeneratedKey(g)
			must(t, h.runner.RunChecks(context.Background()))
			rep := h.lastReport()
			conf, _, _ := h.store.ActiveConfirmation(testfixture.PackageName)
			if !rep.Confirmed || rep.Error != nil || conf.Mode != records.ConfirmModePeerGenerated || conf.CertificateSHA256 != g.CertificateSHA256 {
				t.Fatalf("report %+v confirmation %+v; logs:\n%s", rep, conf, h.logs.String())
			}
		})
	}
}
