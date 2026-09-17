package signer

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/records"
	"github.com/Helix2010/RN-Server/signing/trustroots"
)

// 生成失败报回服务端的 code（约定 3.4）。
const (
	GenerationTrustRootsChanged    = "TRUST_ROOTS_CHANGED"
	GenerationRecoveryKeyNotPinned = "RECOVERY_KEY_NOT_PINNED"
	GenerationNotLocalPrimary      = "NOT_LOCAL_PRIMARY"
	GenerationFailed               = "GENERATION_FAILED"
)

// autoFirstSignHeadroom：自动确认的首签 versionCode 上限 = 已知最大值 + 100（设计第 3 节）。
const autoFirstSignHeadroom = 100

// generationFailure 是报回服务端的生成失败（不是签名闸自己的致命错误）。
type generationFailure struct {
	code   string
	detail string
}

func (g *generationFailure) Error() string { return g.code + ": " + g.detail }

func genFail(code, format string, args ...any) *generationFailure {
	return &generationFailure{code: code, detail: fmt.Sprintf(format, args...)}
}

// confirmationPlan 是按本机记录决定的确认值：首次信任服务端的信任根，或沿用本机已确认的信任根。
type confirmationPlan struct {
	firstTrust bool
	previous   *records.Confirmation
	roots      trustroots.Roots
	digest     string
	minSDK     int64
	targetSDK  int64
	firstCap   int64
}

// planConfirmation 按设计第 3 节决定一个包名的新密钥用什么信任根：
//   - 本机对这个包名没有确认、对这个租户也从没确认过（任何包名）：首次信任服务端的信任根（必须格式合法、
//     摘要对得上），SDK 下限 24/28；
//   - 本机已有确认、租户相同、服务端的信任根摘要与记录相同：沿用原有信任根与 SDK 下限；
//   - 其余（摘要变了、包名换了租户、已确认的租户换了新包名）：TRUST_ROOTS_CHANGED，不生成。
//
// 首签上限：本机对这个包名有签名历史（任何证书）时取历史最大值 + 100，否则取服务端该平台已发布的
// 最大 build 号 + 100（首次信任；服务端没给就按 0）。
func (r *Runner) planConfirmation(tenant, pkg string, serverRoots *trustroots.Roots, serverDigest *string, publishedMax *int64) (confirmationPlan, *generationFailure, error) {
	active, has, err := r.Store.ActiveConfirmation(pkg)
	if err != nil {
		return confirmationPlan{}, nil, err
	}
	var plan confirmationPlan
	if has {
		switch {
		case active.TenantSlug != tenant:
			return plan, genFail(GenerationTrustRootsChanged, "package %s is confirmed for tenant %s on this signing gate, not %s; run signer confirm on this signing gate", pkg, active.TenantSlug, tenant), nil
		case serverDigest == nil || *serverDigest != active.TrustRootsDigest:
			return plan, genFail(GenerationTrustRootsChanged, "the tenant's trust roots differ from the ones confirmed on this signing gate for %s; run signer confirm on this signing gate first", pkg), nil
		}
		previous := active
		plan = confirmationPlan{previous: &previous, roots: active.TrustRoots, digest: active.TrustRootsDigest, minSDK: active.MinSDK, targetSDK: active.TargetSDK}
	} else {
		// 首次信任只给本机从没确认过的租户：已确认的租户换一个包名，服务端就不能借「新包名」把信任根换掉
		if confirmedPackage, known, err := r.Store.TenantConfirmedPackage(tenant); err != nil {
			return confirmationPlan{}, nil, err
		} else if known {
			return plan, genFail(GenerationTrustRootsChanged, "tenant %s is already confirmed on this signing gate for package %s; a keystore for another package (%s) is not generated on first trust: "+
				"import a keystore for it and run signer confirm on every signing gate", tenant, confirmedPackage, pkg), nil
		}
		if serverRoots == nil || serverDigest == nil {
			return plan, genFail(GenerationFailed, "the server has no trust roots for this tenant (is the OTA certificate configured?)"), nil
		}
		normalized, err := serverRoots.Normalize()
		if err != nil || !trustroots.Equal(normalized, *serverRoots) {
			return plan, genFail(GenerationFailed, "the server's trust roots for this tenant are malformed"), nil
		}
		digest, err := trustroots.Digest(normalized)
		if err != nil || digest != *serverDigest {
			return plan, genFail(GenerationFailed, "the server's trust roots digest does not match its trust roots"), nil
		}
		plan = confirmationPlan{firstTrust: true, roots: normalized, digest: digest, minSDK: records.MinConfirmedMinSDK, targetSDK: records.MinConfirmedTargetSDK}
	}
	base := int64(0)
	if localMax, ok, err := r.Store.PackageMaxVersionCode(pkg); err != nil {
		return confirmationPlan{}, nil, err
	} else if ok {
		base = localMax
	} else if publishedMax != nil {
		if *publishedMax < 0 || *publishedMax > records.MaxVersionCode {
			return plan, genFail(GenerationFailed, "the server's published build number is out of range"), nil
		}
		base = *publishedMax
	}
	plan.firstCap = min(base+autoFirstSignHeadroom, records.MaxVersionCode)
	return plan, nil, nil
}

func (p confirmationPlan) confirmation(tenant, pkg, cert, alias string, keystoreVersion int64, mode, requestID, generatorName, generatorEd string) records.Confirmation {
	return records.Confirmation{
		TenantSlug: tenant, PackageName: pkg, CertificateSHA256: cert, KeyAlias: alias, KeystoreVersion: keystoreVersion,
		TrustRoots: p.roots, TrustRootsDigest: p.digest, MinSDK: p.minSDK, TargetSDK: p.targetSDK, FirstSignMaxVersionCode: p.firstCap,
		ConfirmedBy: records.AutoConfirmedBy(mode, generatorName), Mode: mode, GenerationRequestID: requestID,
		GeneratorName: generatorName, GeneratorEd25519SHA256: generatorEd,
	}
}

// ---- 主签名闸：处理生成请求 ----

// processGeneration 处理一个租户项里的生成请求。返回的错误是签名闸的致命错误（本机记录不可用、
// 令牌被拒）；生成本身的失败报回服务端。
func (r *Runner) processGeneration(ctx context.Context, machineID string, item CheckItem) error {
	req := item.GenerationRequest
	if !keystorebox.ValidGenerationRequestID(req.RequestID) {
		// 拼不出上报的 URL：不上报，服务端的请求保持 pending，控制台可见
		r.Log.Warn("the server sent a keystore generation request with a malformed id; ignoring it")
		return nil
	}
	r.mu.Lock()
	done := r.generationsDone[req.RequestID]
	r.mu.Unlock()
	if done {
		return nil
	}
	log := r.Log.With("generationRequest", req.RequestID, "tenant", cleanText(item.TenantSlug, 100))
	failure, err := r.generate(ctx, log, machineID, item)
	if err != nil {
		return err
	}
	if failure == nil {
		return nil
	}
	log.Error("keystore generation refused", "code", failure.code, "detail", failure.detail)
	detail := cleanText(failure.detail, 500)
	err = r.retry(ctx, "report keystore generation failure", func(ctx context.Context) error {
		return r.API.FailGeneration(ctx, req.RequestID, failure.code, detail)
	})
	var apiErr *APIError
	switch {
	case err == nil, errors.As(err, &apiErr) && !apiErr.Transient() && !IsTokenRejected(err):
		// 服务端已记下（或请求已不是 pending）：这个请求不再处理
		r.markGeneration(req.RequestID)
	case IsTokenRejected(err):
		return err
	default:
		log.Warn("could not report the generation failure; retrying next round", "error", err)
	}
	return nil
}

func (r *Runner) markGeneration(requestID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.generationsDone) >= maxTrackedJobs {
		r.generationsDone = map[string]bool{}
	}
	r.generationsDone[requestID] = true
}

// generate 是设计第 3 节「主签名闸」：生成、加密给本机信任的签名闸与恢复公钥、签生成签名、交回，
// 服务端接受之后写自动确认。
func (r *Runner) generate(ctx context.Context, log *slog.Logger, machineID string, item CheckItem) (*generationFailure, error) {
	req := item.GenerationRequest
	switch {
	case !ident.ValidTenantSlug(item.TenantSlug):
		return genFail(GenerationFailed, "the generation request has a malformed tenant slug"), nil
	case !ident.ValidPackageName(req.PackageName):
		return genFail(GenerationFailed, "the generation request has a malformed package name"), nil
	case !ident.ValidKeyAlias(req.Alias):
		return genFail(GenerationFailed, "the generation request has a malformed key alias"), nil
	case !ident.ValidServerID(machineID):
		return genFail(GenerationFailed, "the server did not send this signing gate's machine id"), nil
	}
	role, err := r.Store.Role()
	if err != nil {
		return nil, &fatalError{err}
	}
	if role.Role != records.RolePrimary {
		return genFail(GenerationNotLocalPrimary, "this signing gate is not the primary in its local records (signer promote)"), nil
	}
	plan, failure, err := r.planConfirmation(item.TenantSlug, req.PackageName, req.TrustRoots, req.TrustRootsDigest, req.PublishedMaxBuildNumber)
	if err != nil {
		return nil, &fatalError{err}
	}
	if failure != nil {
		return failure, nil
	}
	pinnedRecovery, err := r.Store.TrustedRecoveryKeys()
	if err != nil {
		return nil, &fatalError{err}
	}
	if len(pinnedRecovery) == 0 {
		return genFail(GenerationRecoveryKeyNotPinned, "this signing gate trusts no offline recovery key (signer trust-recovery)"), nil
	}
	view, err := r.API.Peers(ctx)
	if err != nil {
		if IsTokenRejected(err) {
			return nil, err
		}
		log.Warn("could not fetch the peer list for key generation; retrying next round", "error", err)
		return nil, nil
	}
	chosen, err := r.localRecipients(view)
	if err != nil {
		return nil, &fatalError{err}
	}
	chosen.logSkipped(log, "the new keystore is not encrypted to it")
	if chosen.recoveryCount == 0 {
		return genFail(GenerationRecoveryKeyNotPinned, "none of the %d recovery keys trusted on this signing gate is registered and unrevoked on the server", len(pinnedRecovery)), nil
	}
	recipients, names := chosen.publicKeys(), chosen.names()

	log.Info("generating a keystore", "package", req.PackageName, "firstTrust", plan.firstTrust, "recipients", names)
	binding := &keystorebox.Generation{TrustRootsDigest: plan.digest, MinSDK: plan.minSDK, TargetSDK: plan.targetSDK, FirstSignMaxVersionCode: plan.firstCap}
	if plan.previous != nil {
		binding.SupersedesCertificateSHA256 = plan.previous.CertificateSHA256
	}
	generated, err := GenerateKeystore(GenerateParams{
		RequestID: req.RequestID, TenantSlug: item.TenantSlug, PackageName: req.PackageName, KeyAlias: req.Alias,
		Recipients: recipients, Generator: r.Keys.Ed25519, KeyBits: r.KeyBits, Now: time.Now(), Binding: binding,
	})
	if err != nil {
		return genFail(GenerationFailed, "generating the keystore failed: %v", err), nil
	}
	var result GenerationResult
	err = r.retry(ctx, "submit the generated keystore", func(ctx context.Context) error {
		var err error
		result, err = r.API.SubmitGeneration(ctx, req.RequestID, GenerationSubmit{
			Upload: generated.Upload, Generator: GeneratorRef{MachineID: machineID, Ed25519PublicKeySHA256: r.Keys.Ed25519SHA256()}, Signature: generated.Signature,
		})
		return err
	})
	var apiErr *APIError
	switch {
	case err == nil:
	case IsTokenRejected(err):
		return nil, err
	case errors.As(err, &apiErr) && apiErr.Code == codeKeystoreGenerationStale:
		log.Warn("the server says the generation request is no longer pending; the generated keystore was discarded")
		r.markGeneration(req.RequestID)
		return nil, nil
	case errors.As(err, &apiErr) && !apiErr.Transient():
		return genFail(GenerationFailed, "the server refused the generated keystore: %s %s", apiErr.Code, apiErr.Detail), nil
	default:
		log.Warn("submitting the generated keystore failed; a new keystore is generated next round", "error", err)
		return nil, nil
	}
	r.markGeneration(req.RequestID)
	self := r.Store.Genesis().MachineName
	mode := records.ConfirmModeRegenerated
	if plan.firstTrust {
		mode = records.ConfirmModeFirstGeneration
	}
	conf := plan.confirmation(item.TenantSlug, req.PackageName, generated.CertificateSHA256, req.Alias, result.KeystoreVersion, mode, req.RequestID, self, r.Keys.Ed25519SHA256())
	switch err := r.Store.ConfirmAuto(conf, plan.previous); {
	case errors.Is(err, records.ErrConfirmationChanged), errors.Is(err, records.ErrCertificateSeen):
		log.Error("the server accepted the generated keystore, but the local confirmation changed meanwhile; confirm it with signer confirm", "error", err)
	case err != nil:
		return nil, &fatalError{err}
	default:
		log.Info("generated keystore accepted by the server and confirmed locally", "certificateSha256", generated.CertificateSHA256,
			"keystoreVersion", result.KeystoreVersion, "mode", mode, "firstSignCap", conf.FirstSignMaxVersionCode)
	}
	r.mu.Lock()
	r.checksDue = true
	r.mu.Unlock()
	return nil, nil
}

// ---- 自动接受签名闸生成或重新封装的密钥（备签名闸；主签名闸崩溃恢复时也走这里）----

// acceptGenerated 在本机对 (包名, 证书) 没有有效确认时尝试自动确认：生成者必须是本机，或者（本机是备时）
// 本机信任的签名闸——本机是主时只接受本机签的生成，别的签名闸生成的一律退回 signer confirm，免得两台用同一张
// 证书签而彼此的签名记录互相看不到。生成签名覆盖的 Upload 里必须有发给本机的这个 Box，证书没为这个包名确认过，
// 并按密文里生成者写下的确认参数（keystorebox.Generation）核对：
//   - 本机已有确认：它替换的证书必须是本机当前的证书（挡住重放更早的生成），信任根摘要必须与本机相同；
//     沿用本机的信任根与 SDK 下限，首签上限取生成者的；
//   - 本机没有确认：租户在本机从没确认过（任何包名），服务端给的信任根摘要必须等于生成者确认的摘要，
//     SDK 下限与首签上限取生成者的。
//
// 服务端说是重新封装（sealKind=reseal）的按重新封装签名验证，规则见 acceptResealed。服务端说的种类只决定按哪种
// 签名去验；验过之后还要与密文里的 Generation.Kind 一致，两边对不上一律不接受。
//
// 返回 (确认, 不接受的原因, 致命错误)。
func (r *Runner) acceptGenerated(item CheckItem, material keystoreMaterial) (*records.Confirmation, string, error) {
	g := item.Generator
	if g == nil {
		return nil, "", nil
	}
	kind := sealKindGeneration
	if item.SealKind != nil {
		kind = *item.SealKind
	}
	if kind != sealKindGeneration && kind != sealKindReseal {
		return nil, "the server sent an unknown sealKind for this keystore; run signer confirm", nil
	}
	if item.GenerationRequestID == nil || item.Upload == nil || item.GenerationSignature == nil {
		return nil, "the keystore was generated by a signing gate, but the server did not send the generation request id, upload and signature needed to verify it; run signer confirm", nil
	}
	pub, err := base64.StdEncoding.Strict().DecodeString(g.Ed25519PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || fingerprint.SHA256Hex(pub) != g.Ed25519PublicKeySHA256 {
		return nil, "the server's generator public key is malformed", nil
	}
	self := r.Store.Genesis()
	var generatorName, mode string
	if g.Ed25519PublicKeySHA256 == self.Ed25519PublicKeySHA256 {
		if kind == sealKindReseal {
			// 本机只重新封装本机已确认的证书；走到这里说明本机对这张证书已经没有有效确认（被取代了，或者换了租户）
			return nil, "this signing gate resealed this keystore itself, but its certificate is not the one confirmed for the package here any more; run signer confirm if this key is expected", nil
		}
		generatorName = self.MachineName
	} else {
		role, err := r.Store.Role()
		if err != nil {
			return nil, "", err
		}
		if role.Role == records.RolePrimary {
			return nil, fmt.Sprintf("this signing gate is the primary in its local records and only accepts keystores it generated itself (this one was generated or resealed by ed25519 %s); run signer confirm if this key is expected", g.Ed25519PublicKeySHA256), nil
		}
		peers, err := r.Store.TrustedPeers()
		if err != nil {
			return nil, "", err
		}
		for _, p := range peers {
			if p.Ed25519PublicKeySHA256 == g.Ed25519PublicKeySHA256 {
				generatorName, mode = p.Name, records.ConfirmModePeerGenerated
			}
		}
		if generatorName == "" {
			return nil, fmt.Sprintf("the keystore was generated or resealed by a signing gate this machine does not trust (ed25519 %s); run signer trust-peer on this machine, or signer confirm", g.Ed25519PublicKeySHA256), nil
		}
	}
	upload := *item.Upload
	if kind == sealKindReseal {
		if !keystorebox.ValidResealID(*item.GenerationRequestID) || keystorebox.VerifyReseal(pub, *item.GenerationRequestID, upload, *item.GenerationSignature) != nil {
			return nil, "the keystore reseal signature does not verify; refusing to accept the keystore automatically", nil
		}
	} else if err := keystorebox.VerifyGeneration(pub, *item.GenerationRequestID, upload, *item.GenerationSignature); err != nil {
		return nil, "the keystore generation signature does not verify; refusing to accept the keystore automatically", nil
	}
	own, ok := upload.BoxFor(r.Keys.X25519SHA256())
	if !ok || item.Box == nil || own != *item.Box || upload.TenantSlug != item.TenantSlug || upload.PackageName != item.PackageName ||
		upload.CertificateSHA256 != item.CertificateSHA256 || upload.KeyAlias != material.Plain.KeyAlias || upload.CreatedAt != material.Plain.CreatedAt {
		return nil, "the keystore sent to this signing gate is not the one covered by the generation signature", nil
	}
	// 生成者写下的确认参数在密文里（Box 密文被签名覆盖），服务端改不了
	bound := material.Plain.Generation
	switch {
	case bound == nil:
		return nil, "the keystore carries no generation parameters from its generator; run signer confirm", nil
	case kind == sealKindReseal && bound.Kind != keystorebox.GenerationKindReseal:
		return nil, "the keystore was sent as a reseal, but its sealed parameters are not a reseal; run signer confirm", nil
	case kind == sealKindGeneration && bound.Kind != "":
		return nil, "the keystore was sent as a generation, but its sealed parameters are a reseal; run signer confirm", nil
	case kind == sealKindReseal:
		return r.acceptResealed(item, material, bound, generatorName, g.Ed25519PublicKeySHA256)
	}
	seen, err := r.Store.CertificateSeen(item.PackageName, item.CertificateSHA256)
	if err != nil {
		return nil, "", err
	}
	if seen {
		return nil, "this certificate was confirmed for this package before and later replaced; switching back needs signer confirm", nil
	}
	active, has, err := r.Store.ActiveConfirmation(item.PackageName)
	if err != nil {
		return nil, "", err
	}
	var plan confirmationPlan
	if has {
		switch {
		case active.TenantSlug != item.TenantSlug:
			return nil, fmt.Sprintf("%s: package %s is confirmed for tenant %s on this signing gate, not %s; run signer confirm", GenerationTrustRootsChanged, item.PackageName, active.TenantSlug, item.TenantSlug), nil
		case bound.SupersedesCertificateSHA256 != active.CertificateSHA256:
			// 生成者生成时替换的不是本机当前的证书：可能是服务端重放了更早的一次生成，或本机错过了中间一次换密钥
			return nil, fmt.Sprintf("the keystore replaces certificate %q, but this signing gate's current certificate for %s is %s; run signer confirm if this key is expected", bound.SupersedesCertificateSHA256, item.PackageName, active.CertificateSHA256), nil
		case bound.TrustRootsDigest != active.TrustRootsDigest:
			return nil, fmt.Sprintf("%s: the generator confirmed different trust roots than this signing gate for %s; run signer confirm", GenerationTrustRootsChanged, item.PackageName), nil
		}
		previous := active
		plan = confirmationPlan{previous: &previous, roots: active.TrustRoots, digest: active.TrustRootsDigest, minSDK: active.MinSDK, targetSDK: active.TargetSDK, firstCap: bound.FirstSignMaxVersionCode}
	} else {
		// 首次信任只给本机从没确认过的租户（与主签名闸的规则相同）
		if confirmedPackage, known, err := r.Store.TenantConfirmedPackage(item.TenantSlug); err != nil {
			return nil, "", err
		} else if known {
			return nil, fmt.Sprintf("%s: tenant %s is already confirmed on this signing gate for package %s; a keystore for package %s is not accepted on first trust; run signer confirm", GenerationTrustRootsChanged, item.TenantSlug, confirmedPackage, item.PackageName), nil
		}
		// 首次信任：只接受与生成者确认的摘要一致的服务端信任根
		if item.TrustRoots == nil {
			return nil, "the server sent no trust roots for this tenant", nil
		}
		normalized, err := item.TrustRoots.Normalize()
		if err != nil || !trustroots.Equal(normalized, *item.TrustRoots) {
			return nil, "the server's trust roots for this tenant are malformed", nil
		}
		if digest, err := trustroots.Digest(normalized); err != nil || digest != bound.TrustRootsDigest {
			return nil, fmt.Sprintf("%s: the server's trust roots are not the ones the generator confirmed for %s; refusing to trust them", GenerationTrustRootsChanged, item.PackageName), nil
		}
		plan = confirmationPlan{firstTrust: true, roots: normalized, digest: bound.TrustRootsDigest, minSDK: bound.MinSDK, targetSDK: bound.TargetSDK, firstCap: bound.FirstSignMaxVersionCode}
	}
	if mode == "" {
		mode = records.ConfirmModeRegenerated
		if plan.firstTrust {
			mode = records.ConfirmModeFirstGeneration
		}
	}
	conf := plan.confirmation(item.TenantSlug, item.PackageName, item.CertificateSHA256, material.Plain.KeyAlias, item.KeystoreVersion, mode,
		*item.GenerationRequestID, generatorName, g.Ed25519PublicKeySHA256)
	return r.confirmAutomatically(conf, plan.previous, "accepted a keystore generated by a trusted signing gate")
}

// confirmAutomatically 写自动确认（ConfirmAuto），把"计划之后本机记录变了""参数不合本机规则"翻成不接受的原因。
func (r *Runner) confirmAutomatically(conf records.Confirmation, previous *records.Confirmation, logMessage string) (*records.Confirmation, string, error) {
	switch err := r.Store.ConfirmAuto(conf, previous); {
	case errors.Is(err, records.ErrConfirmationChanged), errors.Is(err, records.ErrCertificateSeen):
		return nil, "the local confirmation changed while accepting the keystore automatically; it is retried next round", nil
	case err != nil:
		// 生成者给的 SDK 下限、首签上限不合本机记录的规则（例如低于 24/28）也落在这里：不接受，要运维确认
		if strings.Contains(err.Error(), "records: confirmation:") {
			return nil, "the generator's confirmation parameters are not acceptable on this signing gate (" + cleanText(err.Error(), 200) + "); run signer confirm", nil
		}
		return nil, "", err
	}
	r.Log.Info(logMessage, "tenant", conf.TenantSlug, "package", conf.PackageName,
		"certificateSha256", conf.CertificateSHA256, "generator", conf.GeneratorName, "mode", conf.Mode, "firstSignCap", conf.FirstSignMaxVersionCode)
	return &conf, "", nil
}
