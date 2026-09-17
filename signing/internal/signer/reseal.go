package signer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/records"
	"github.com/Helix2010/RN-Server/signing/trustroots"
)

// 同证书重新封装（设计「同证书重新封装」、ADR-0020 第 7 节）。
//
// 密钥原来只在生成（或离线导入）时加密给当时的收件人，后加或替换的签名闸拿不到已有租户的密钥。主签名闸每轮检查时，
// 对本机已确认的每份密钥看一眼：本机决定的收件人（本机；本机信任、服务端 active 且公钥指纹与本机记录一致的签名闸；
// 本机信任、服务端未吊销的恢复公钥）里有没有不在当前收件人里的。有就把本机解开的同一份明文（同一张证书、同样的
// 口令与原件）重新加密给这组收件人，明文里写下本机对这张证书的当前确认参数（Generation.Kind=reseal），用本机
// Ed25519 签 keystorebox.ResealMessage 交回。后加的签名闸在本机 trust-peer 了主签名闸之后，按这份签名与参数首次
// 信任（acceptResealed）。
//
// 服务端被攻破时能做的：不报、少报、乱报收件人与签名闸状态，结果是不重新封装（拒绝服务），或者重新封装给本机本来就
// 信任的那组收件人；加不进任何本机没信任的公钥。

// resealWindow：同一租户在本进程里两次尝试重新封装至少隔这么久。服务端每轮报的收件人都在变（异常或被攻破）时，
// 不至于每分钟重新加密、交回一次。
const resealWindow = 10 * time.Minute

// resealCandidate 是一份可能要重新封装的密钥（checkItem 判过：本机是主、本机确认过这张证书、服务端信任根与确认一致、
// 自己那份解开了且外层字段一致、没有待交回的生成请求）。
type resealCandidate struct {
	item     CheckItem
	material keystoreMaterial
	conf     records.Confirmation
	// report 是这一项检查结论在本轮上报列表里的下标
	report int
}

// resealPlan 是决定要做的一次重新封装。
type resealPlan struct {
	candidate resealCandidate
	choice    recipientChoice
	added     []string
	removed   []string
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// ---- 本机决定的收件人（生成与重新封装共用）----

type sealRecipient struct {
	name     string
	sha      string
	pub      []byte
	recovery bool
}

// recipientChoice 是本机决定的收件人，以及本机信任、但这次没加进去的（服务端没把它报成 active、公钥对不上、已吊销）。
type recipientChoice struct {
	recipients    []sealRecipient
	recoveryCount int
	skippedPeers  []string
	skippedKeys   []string
}

// localRecipients：本机；本机信任、且服务端视图里 active、两个公钥指纹与本机记录一致的签名闸；本机信任、且服务端登记
// 未吊销、公钥与指纹一致的恢复公钥。服务端多登记的签名闸与恢复公钥一概不加。
func (r *Runner) localRecipients(view PeersResponse) (recipientChoice, error) {
	peers, err := r.Store.TrustedPeers()
	if err != nil {
		return recipientChoice{}, err
	}
	pinnedRecovery, err := r.Store.TrustedRecoveryKeys()
	if err != nil {
		return recipientChoice{}, err
	}
	out := recipientChoice{recipients: []sealRecipient{{name: r.Store.Genesis().MachineName, sha: r.Keys.X25519SHA256(), pub: r.Keys.X25519PublicKey()}}}
	for _, p := range peers {
		var key []byte
		for _, s := range view.Signers {
			v, err := verifyPeerSigner(s)
			if err == nil && v.X25519PublicKeySHA256 == p.X25519PublicKeySHA256 && v.Ed25519PublicKeySHA256 == p.Ed25519PublicKeySHA256 {
				key = v.X25519
			}
		}
		if key == nil {
			out.skippedPeers = append(out.skippedPeers, p.Name)
			continue
		}
		out.recipients = append(out.recipients, sealRecipient{name: p.Name, sha: p.X25519PublicKeySHA256, pub: key})
	}
	for _, k := range pinnedRecovery {
		var key []byte
		for _, s := range view.RecoveryKeys {
			if s.X25519PublicKeySHA256 != k.X25519PublicKeySHA256 || s.Revoked {
				continue
			}
			if pub, err := verifyPeerRecoveryKey(s); err == nil {
				key = pub
			}
		}
		if key == nil {
			out.skippedKeys = append(out.skippedKeys, k.Name)
			continue
		}
		out.recipients = append(out.recipients, sealRecipient{name: "recovery:" + k.Name, sha: k.X25519PublicKeySHA256, pub: key, recovery: true})
		out.recoveryCount++
	}
	return out, nil
}

func (c recipientChoice) logSkipped(log *slog.Logger, consequence string) {
	for _, name := range c.skippedPeers {
		log.Warn("a trusted signing gate is not active on the server with the trusted keys; "+consequence, "peer", name)
	}
	for _, name := range c.skippedKeys {
		log.Warn("a trusted recovery key is missing or revoked on the server; "+consequence, "recoveryKey", name)
	}
}

func (c recipientChoice) publicKeys() [][]byte {
	out := make([][]byte, 0, len(c.recipients))
	for _, rec := range c.recipients {
		out = append(out, rec.pub)
	}
	return out
}

func (c recipientChoice) names() []string {
	out := make([]string, 0, len(c.recipients))
	for _, rec := range c.recipients {
		out = append(out, rec.name)
	}
	return out
}

func (c recipientChoice) shas() []string {
	out := make([]string, 0, len(c.recipients))
	for _, rec := range c.recipients {
		out = append(out, rec.sha)
	}
	sort.Strings(out)
	return out
}

// ---- 主签名闸：决定与执行 ----

// planReseals 从候选里挑出要重新封装的（设计条件 4–6）：本机决定的收件人里有不在服务端所报收件人里的；其中至少
// 一把恢复公钥（一把都没有就不做，在这一项的检查结论里报 RECOVERY_KEY_NOT_PINNED）；这个租户本进程 10 分钟内
// 没有尝试过。服务端报的收件人只多不少（多出本机没信任的）不触发：服务端报的状态抖动不会引起反复封装。
//
// 本机信任的收件人全都在当前收件人里时不问服务端（多数轮次如此）。返回的错误是致命的（本机记录不可用、令牌被拒）。
func (r *Runner) planReseals(ctx context.Context, candidates []resealCandidate, reports []CheckReport) ([]resealPlan, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	peers, err := r.Store.TrustedPeers()
	if err != nil {
		return nil, err
	}
	pinnedRecovery, err := r.Store.TrustedRecoveryKeys()
	if err != nil {
		return nil, err
	}
	// 本机决定的收件人只会是本机信任的这些里的一部分
	trusted := []string{r.Keys.X25519SHA256()}
	for _, p := range peers {
		trusted = append(trusted, p.X25519PublicKeySHA256)
	}
	for _, k := range pinnedRecovery {
		trusted = append(trusted, k.X25519PublicKeySHA256)
	}
	var needed []resealCandidate
	for _, c := range candidates {
		if len(missingFrom(trusted, c.item.Recipients)) > 0 {
			needed = append(needed, c)
		}
	}
	if len(needed) == 0 {
		return nil, nil
	}
	view, err := r.API.Peers(ctx)
	if err != nil {
		if IsTokenRejected(err) {
			return nil, err
		}
		r.Log.Warn("could not fetch the peer list to check keystore recipients; checked again next round", "error", err)
		return nil, nil
	}
	choice, err := r.localRecipients(view)
	if err != nil {
		return nil, err
	}
	desired := choice.shas()
	var plans []resealPlan
	for _, c := range needed {
		missing := missingFrom(desired, c.item.Recipients)
		if len(missing) == 0 {
			continue
		}
		log := r.Log.With("tenant", cleanText(c.item.TenantSlug, 100), "package", c.item.PackageName)
		if choice.recoveryCount == 0 {
			detail := fmt.Sprintf("%s: the keystore is not sealed to every signing gate this primary trusts, but none of the %d recovery keys trusted here is registered and unrevoked on the server, so it is not resealed (signer trust-recovery)",
				GenerationRecoveryKeyNotPinned, len(pinnedRecovery))
			log.Warn("not resealing a keystore without a recovery recipient", "detail", detail)
			if c.report >= 0 && reports[c.report].Error == nil {
				m := cleanText(detail, 300)
				reports[c.report].Error = &m
			}
			continue
		}
		if !r.mayReseal(c.item.TenantSlug) {
			log.Debug("a reseal was attempted for this tenant less than 10 minutes ago; waiting")
			continue
		}
		plans = append(plans, resealPlan{candidate: c, choice: choice, added: namesOf(choice, missing, view), removed: namesOf(choice, missingFrom(c.item.Recipients, desired), view)})
	}
	return plans, nil
}

// missingFrom 返回 want 里不在 have 里的指纹。
func missingFrom(want, have []string) []string {
	present := make(map[string]bool, len(have))
	for _, h := range have {
		present[h] = true
	}
	var out []string
	for _, w := range want {
		if !present[w] {
			out = append(out, w)

		}
	}
	return out
}

// namesOf 给日志用：本机记录里的名字，其次服务端视图里的名字（只作显示），都没有就是指纹。
func namesOf(choice recipientChoice, shas []string, view PeersResponse) []string {
	out := make([]string, 0, len(shas))
	for _, sha := range shas {
		name := sha
		for _, s := range view.Signers {
			if s.X25519PublicKeySHA256 == sha {
				name = "server:" + cleanText(s.Name, 40)
			}
		}
		for _, k := range view.RecoveryKeys {
			if k.X25519PublicKeySHA256 == sha {
				name = "server:recovery:" + cleanText(k.Name, 40)
			}
		}
		for _, rec := range choice.recipients {
			if rec.sha == sha {
				name = rec.name
			}
		}
		out = append(out, name)
	}
	return out
}

func (r *Runner) mayReseal(tenant string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	last, ok := r.resealAttempts[tenant]
	return !ok || r.now().Sub(last) >= resealWindow
}

func (r *Runner) markReseal(tenant string, attempted bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !attempted {
		delete(r.resealAttempts, tenant)
		return
	}
	if len(r.resealAttempts) >= maxTrackedJobs {
		r.resealAttempts = map[string]time.Time{}
	}
	r.resealAttempts[tenant] = r.now()
}

// reseal 按计划重新封装并交回。返回的错误只有令牌被拒（签名闸停下）；其余失败记日志，按节奏下次再看。
func (r *Runner) reseal(ctx context.Context, plan resealPlan) error {
	c := plan.candidate
	item, plain, conf := c.item, c.material.Plain, c.conf
	log := r.Log.With("tenant", item.TenantSlug, "package", item.PackageName, "certificateSha256", item.CertificateSHA256)
	r.markReseal(item.TenantSlug, true)
	resealID, err := newResealID()
	if err != nil {
		log.Error("could not create a reseal id", "error", err)
		return nil
	}
	// 同一份明文：原件、口令、证书、别名、包名、租户、createdAt 都不变；换的只有收件人与确认参数。确认参数取本机对
	// 这张证书当前有效的确认，后加的签名闸按它首次信任
	resealed := plain
	resealed.Recipients = plan.choice.shas()
	resealed.Generation = &keystorebox.Generation{
		TrustRootsDigest: conf.TrustRootsDigest, MinSDK: conf.MinSDK, TargetSDK: conf.TargetSDK, FirstSignMaxVersionCode: conf.FirstSignMaxVersionCode,
		SupersedesCertificateSHA256: conf.CertificateSHA256, Kind: keystorebox.GenerationKindReseal,
	}
	upload := keystorebox.Upload{
		Format: keystorebox.UploadFormat, TenantSlug: plain.TenantSlug, PackageName: plain.PackageName, KeyAlias: plain.KeyAlias,
		CertificateSHA256: plain.CertificateSHA256, CreatedAt: plain.CreatedAt,
	}
	for _, rec := range plan.choice.recipients {
		box, err := keystorebox.Seal(resealed, rec.pub)
		if err != nil {
			log.Error("could not reseal the keystore", "error", err)
			return nil
		}
		upload.Boxes = append(upload.Boxes, box)
	}
	signature, err := keystorebox.SignReseal(r.Keys.Ed25519, resealID, upload)
	if err != nil {
		log.Error("could not sign the resealed keystore", "error", err)
		return nil
	}
	log.Info("resealing a keystore to the recipients this primary trusts", "resealId", resealID, "added", plan.added, "removed", plan.removed)
	var result ResealResult
	err = r.retry(ctx, "submit the resealed keystore", func(ctx context.Context) error {
		var err error
		result, err = r.API.SubmitReseal(ctx, ResealSubmit{TenantSlug: item.TenantSlug, KeystoreVersion: item.KeystoreVersion, ResealID: resealID, Upload: upload, Signature: signature})
		return err
	})
	var apiErr *APIError
	switch {
	case err == nil:
		log.Info("resealed keystore accepted by the server", "resealId", resealID, "keystoreVersion", result.KeystoreVersion, "added", plan.added, "removed", plan.removed)
		r.mu.Lock()
		r.checksDue = true
		r.mu.Unlock()
	case IsTokenRejected(err):
		return err
	case errors.As(err, &apiErr) && (apiErr.Code == codeKeystoreResealStale || apiErr.Code == codeKeystoreGenerationInProgress):
		// 密钥刚换了版本，或者有生成在进行：下一轮按新的记录再看，不占 10 分钟窗口
		r.markReseal(item.TenantSlug, false)
		log.Info("the server did not take the resealed keystore now; checked again next round", "code", apiErr.Code)
	default:
		log.Error("the server refused the resealed keystore or could not be reached; tried again in 10 minutes", "error", err)
	}
	return nil
}

func newResealID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return keystorebox.ResealIDPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// ---- 备签名闸：接受重新封装 ----

// acceptResealed 是 acceptGenerated 里服务端说是重新封装、封装者是本机信任的签名闸（本机是备）、重新封装签名验证
// 通过、密文里的参数确实是重新封装（Kind=reseal，替换的证书就是它自己）之后的规则：
//   - 本机对这个包名确认的是另一张证书：不接受。重新封装不能换证书，换证书只能 signer confirm；
//   - 本机对这个包名没有任何确认（后加的签名闸）：租户在本机从没确认过（任何包名），服务端给的信任根与摘要都等于封装者
//     确认的摘要，按封装者的 SDK 下限与首签上限首次信任，记为 auto:peer-resealed:<封装者>。
//
// 本机对这张证书已有有效确认时根本不走到这里：box 解得开、证书相同就照常用，不需要签名。
func (r *Runner) acceptResealed(item CheckItem, material keystoreMaterial, bound *keystorebox.Generation, sealerName, sealerEd25519 string) (*records.Confirmation, string, error) {
	active, has, err := r.Store.ActiveConfirmation(item.PackageName)
	if err != nil {
		return nil, "", err
	}
	if has {
		if active.CertificateSHA256 != item.CertificateSHA256 {
			return nil, fmt.Sprintf("a reseal keeps the certificate, and this signing gate has confirmed certificate %s for %s, not %s; a different certificate is accepted only with signer confirm",
				active.CertificateSHA256, item.PackageName, item.CertificateSHA256), nil
		}
		return nil, fmt.Sprintf("%s: package %s is confirmed for tenant %s on this signing gate, not %s; run signer confirm", GenerationTrustRootsChanged, item.PackageName, active.TenantSlug, item.TenantSlug), nil
	}
	if confirmedPackage, known, err := r.Store.TenantConfirmedPackage(item.TenantSlug); err != nil {
		return nil, "", err
	} else if known {
		return nil, fmt.Sprintf("%s: tenant %s is already confirmed on this signing gate for package %s; a resealed keystore for package %s is not accepted on first trust; run signer confirm", GenerationTrustRootsChanged, item.TenantSlug, confirmedPackage, item.PackageName), nil
	}
	if item.TrustRoots == nil || item.TrustRootsDigest == nil {
		return nil, "the server sent no trust roots for this tenant", nil
	}
	normalized, err := item.TrustRoots.Normalize()
	if err != nil || !trustroots.Equal(normalized, *item.TrustRoots) {
		return nil, "the server's trust roots for this tenant are malformed", nil
	}
	if digest, err := trustroots.Digest(normalized); err != nil || digest != bound.TrustRootsDigest || *item.TrustRootsDigest != bound.TrustRootsDigest {
		return nil, fmt.Sprintf("%s: the server's trust roots are not the ones the resealing signing gate confirmed for %s; refusing to trust them", GenerationTrustRootsChanged, item.PackageName), nil
	}
	plan := confirmationPlan{firstTrust: true, roots: normalized, digest: bound.TrustRootsDigest, minSDK: bound.MinSDK, targetSDK: bound.TargetSDK, firstCap: bound.FirstSignMaxVersionCode}
	conf := plan.confirmation(item.TenantSlug, item.PackageName, item.CertificateSHA256, material.Plain.KeyAlias, item.KeystoreVersion, records.ConfirmModePeerResealed,
		*item.GenerationRequestID, sealerName, sealerEd25519)
	return r.confirmAutomatically(conf, nil, "accepted a keystore resealed by a trusted signing gate")
}
