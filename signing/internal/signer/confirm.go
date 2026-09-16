package signer

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/pkcs12"
	"github.com/Helix2010/RN-Server/signing/records"
	"github.com/Helix2010/RN-Server/signing/trustroots"
)

// ErrFingerprintMismatch：运维粘贴的证书指纹与本机从密文里算出的不一致。
var ErrFingerprintMismatch = errors.New("the pasted certificate fingerprint does not match the certificate inside the keystore sent to this signing gate; nothing was written")

// OperatorEnv 是运维子命令需要的依赖。
type OperatorEnv struct {
	Config Config
	Keys   MachineKeys
	Store  *records.Store
	API    API
	Term   Terminal
}

// Confirm 是设计「signer confirm」的 5 步。不以服务端下发的任何值为依据：
// 证书指纹由本机私钥解开密文后自己算，运维粘贴离线记录比对；信任根逐项由运维输入，
// 服务端的值只作对照显示（且只在通过严格格式校验后才显示）。
func Confirm(ctx context.Context, env OperatorEnv, tenantSlug string) error {
	t := env.Term
	if !ident.ValidTenantSlug(tenantSlug) {
		return errors.New("--tenant is not a valid tenant slug")
	}
	resp, err := env.API.KeystoreChecks(ctx)
	if err != nil {
		return fmt.Errorf("fetch the keystores addressed to this signing gate: %w", err)
	}
	var items []CheckItem
	for _, item := range resp.Items {
		if item.TenantSlug == tenantSlug {
			items = append(items, item)
		}
	}
	switch len(items) {
	case 0:
		return fmt.Errorf("the server has no keystore for tenant %s addressed to this signing gate (upload one in the console first)", tenantSlug)
	case 1:
	default:
		return fmt.Errorf("the server returned %d keystores for tenant %s; expected exactly one", len(items), tenantSlug)
	}
	item := items[0]
	serverRoots, err := validateServerItem(item)
	if err != nil {
		// 不打印原值：它可能含终端控制字符，用来伪造屏幕内容
		return fmt.Errorf("the server's keystore record for tenant %s is malformed (%v); refusing to display or use it", tenantSlug, err)
	}

	// 第 2 步：本机私钥解开，自己算证书指纹
	material, err := openKeystore(item.Box, env.Keys, expectedIdentity{tenantSlug, item.PackageName, item.CertificateSHA256})
	if err != nil {
		return fmt.Errorf("the keystore sent to this signing gate is unusable: %w", err)
	}
	entry, err := pkcs12.FindKey(material.P12, material.Plain.StorePassword, material.Plain.KeyAlias)
	if err != nil {
		return fmt.Errorf("the keystore sent to this signing gate is unusable: %w", err)
	}
	computedCert := pkcs12.CertificateSHA256(entry)
	plain := material.Plain
	material = keystoreMaterial{}

	printf(t, "\n确认租户签名密钥 / Confirm a tenant signing key\n")
	printf(t, "  tenant (from the decrypted keystore):   %s\n", plain.TenantSlug)
	printf(t, "  package (from the decrypted keystore):  %s\n", plain.PackageName)
	printf(t, "  key alias (from the decrypted keystore): %s\n", plain.KeyAlias)
	printf(t, "  keystore version on the server:         %d\n", item.KeystoreVersion)
	printf(t, "  recipients bound in the keystore:       %d signing gate(s)\n\n", len(plain.Recipients))

	operator, err := ask(t, "Your operator name (recorded as confirmedBy): ", func(s string) error {
		if !records.ValidOperator(s) {
			return errors.New("use letters, digits, . _ @ - (at most 64)")
		}
		return nil
	})
	if err != nil {
		return err
	}

	// 第 3 步：粘贴离线记录里的完整证书指纹
	pasted, err := t.ReadLine("Paste the certificate SHA-256 recorded when the key was generated (64 hex characters): ")
	if err != nil {
		return err
	}
	normalized, ok := fingerprint.Normalize(strings.TrimSpace(pasted))
	if !ok {
		return fmt.Errorf("%w (the pasted value is not a 64-character hex SHA-256)", ErrAborted)
	}
	if normalized != computedCert {
		return ErrFingerprintMismatch
	}
	printf(t, "  ✓ certificate fingerprint matches the keystore: %s\n\n", computedCert)

	// 第 4 步：信任根逐项由运维输入
	ref := func(v string) string {
		if serverRoots == nil {
			return "(the server has no trust roots for this tenant yet)"
		}
		return v
	}
	var roots trustroots.Roots
	printf(t, "Enter the trust roots from your offline record. The server's values are shown for reference only.\n")
	printf(t, "  server apiBaseUrl: %s\n", ref(serverRootsField(serverRoots, "api")))
	if roots.APIBaseURL, err = ask(t, "API origin (type it, e.g. https://api.example.com): ", trustroots.ValidateAPIBaseURL); err != nil {
		return err
	}
	printf(t, "  server otaCertificateSha256: %s\n", ref(serverRootsField(serverRoots, "ota")))
	if roots.OTACertificateSHA256, err = askNormalized(t, "OTA certificate SHA-256 (paste from the offline record): ", func(s string) (string, bool) { return fingerprint.Normalize(s) }); err != nil {
		return err
	}
	printf(t, "  server bootstrapSignerAddress: %s\n", ref(serverRootsField(serverRoots, "address")))
	if roots.BootstrapSignerAddress, err = askNormalized(t, "Bootstrap signer address (paste from the offline record): ", func(s string) (string, bool) {
		v, err := trustroots.NormalizeAddress(s)
		return v, err == nil
	}); err != nil {
		return err
	}
	derived, _ := trustroots.AppLinksHostFor(roots.APIBaseURL)
	printf(t, "  server appLinksHosts: %s   (RN-App derives %s from the API origin)\n", ref(serverRootsField(serverRoots, "hosts")), derived)
	hostsLine, err := ask(t, "App Links hosts (type them, comma-separated): ", func(s string) error {
		_, err := trustroots.NormalizeHosts(splitList(s))
		return err
	})
	if err != nil {
		return err
	}
	roots.AppLinksHosts = splitList(hostsLine)
	printf(t, "  server scheme: %s\n", ref(serverRootsField(serverRoots, "scheme")))
	if roots.Scheme, err = ask(t, "Custom scheme (type it): ", func(s string) error {
		probe := validRootsProbe()
		probe.Scheme = s
		_, err := probe.Normalize()
		return err
	}); err != nil {
		return err
	}
	printf(t, "  server distributionChannel: %s\n", ref(serverRootsField(serverRoots, "channel")))
	if roots.DistributionChannel, err = ask(t, "Distribution channel (type it: "+strings.Join(trustroots.DistributionChannels, ", ")+"): ", func(s string) error {
		probe := validRootsProbe()
		probe.DistributionChannel = s
		_, err := probe.Normalize()
		return err
	}); err != nil {
		return err
	}
	printf(t, "  server applicationId: %s\n", ref(serverRootsField(serverRoots, "appId")))
	if roots.ApplicationID, err = ask(t, "Application id (type it): ", func(s string) error {
		probe := validRootsProbe()
		probe.ApplicationID = s
		_, err := probe.Normalize()
		return err
	}); err != nil {
		return err
	}
	roots, err = roots.Normalize()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAborted, err)
	}
	digest, err := trustroots.Digest(roots)
	if err != nil {
		return err
	}
	// 签名闸只签 v2/v3：minSdk 低于 24 的设备装不上；targetSdk 不低于 28 时明文流量缺省关闭
	minSDK, err := askInt(t, fmt.Sprintf("minSdkVersion floor (packages below it are refused; at least %d): ", records.MinConfirmedMinSDK), records.MinConfirmedMinSDK, 1000)
	if err != nil {
		return err
	}
	targetSDK, err := askInt(t, fmt.Sprintf("targetSdkVersion floor (at least %d and not below minSdk): ", max(minSDK, records.MinConfirmedTargetSDK)), max(minSDK, records.MinConfirmedTargetSDK), 1000)
	if err != nil {
		return err
	}
	view, err := env.Store.SignedState(plain.PackageName, computedCert, "", "")
	if err != nil {
		return err
	}
	if view.HasMax {
		printf(t, "  this signing gate has already signed up to versionCode %d for this package and certificate; the cap below only applies to a first signature\n", view.Max)
	}
	firstCap, err := askInt(t, "First-sign versionCode cap (check the offline release record): ", 1, records.MaxVersionCode)
	if err != nil {
		return err
	}

	printf(t, "\nSummary\n")
	summaryLine := func(name, value, server string) {
		mark := "matches the server"
		if serverRoots == nil {
			mark = "server has none"
		} else if value != server {
			mark = "DIFFERS from the server"
		}
		printf(t, "  %-24s %s   [%s]\n", name, value, mark)
	}
	summaryLine("apiBaseUrl", roots.APIBaseURL, serverRootsField(serverRoots, "api"))
	summaryLine("otaCertificateSha256", roots.OTACertificateSHA256, serverRootsField(serverRoots, "ota"))
	summaryLine("bootstrapSignerAddress", roots.BootstrapSignerAddress, serverRootsField(serverRoots, "address"))
	summaryLine("appLinksHosts", strings.Join(roots.AppLinksHosts, ","), serverRootsField(serverRoots, "hosts"))
	summaryLine("scheme", roots.Scheme, serverRootsField(serverRoots, "scheme"))
	summaryLine("distributionChannel", roots.DistributionChannel, serverRootsField(serverRoots, "channel"))
	summaryLine("applicationId", roots.ApplicationID, serverRootsField(serverRoots, "appId"))
	printf(t, "  %-24s %s\n  %-24s %d / %d\n  %-24s %d\n", "trustRootsDigest", digest, "min/target SDK floors", minSDK, targetSDK, "first-sign cap", firstCap)
	// 同一包名只有一份有效确认：新确认取代旧的，旧证书从此不能再签
	active, hasActive, err := env.Store.ActiveConfirmation(plain.PackageName)
	if err != nil {
		return err
	}
	if hasActive {
		printf(t, "\n  ! This replaces the active confirmation for package %s (tenant %s, certificate %s, confirmed at %s by %s).\n",
			active.PackageName, active.TenantSlug, active.CertificateSHA256, active.ConfirmedAt, active.ConfirmedBy)
		if active.TenantSlug != plain.TenantSlug {
			printf(t, "  ! The package moves from tenant %s to tenant %s.\n", active.TenantSlug, plain.TenantSlug)
		}
		if active.CertificateSHA256 != computedCert {
			printf(t, "  ! The certificate changes: devices with the old build cannot upgrade in place, and this signing gate stops signing with the old certificate.\n")
		}
	}
	if item.TrustRootsDigest == nil || *item.TrustRootsDigest != digest {
		printf(t, "\n  ! The server's current trust roots differ from what you entered. Packages the server builds now will be refused\n    and the tenant will not be ready until the tenant configuration matches your offline record.\n")
	}
	if err := confirmTyped(t, "\nType the tenant slug to write this confirmation: ", tenantSlug); err != nil {
		return err
	}

	// 第 5 步：写 trust.jsonl
	if err := env.Store.Confirm(records.Confirmation{
		TenantSlug: plain.TenantSlug, PackageName: plain.PackageName, CertificateSHA256: computedCert, KeyAlias: plain.KeyAlias,
		KeystoreVersion: item.KeystoreVersion, TrustRoots: roots, TrustRootsDigest: digest,
		MinSDK: minSDK, TargetSDK: targetSDK, FirstSignMaxVersionCode: firstCap, ConfirmedBy: operator,
	}); err != nil {
		return fmt.Errorf("write the confirmation: %w", err)
	}
	printf(t, "  ✓ written to trust.jsonl\n")
	report := CheckReport{TenantSlug: tenantSlug, KeystoreVersion: item.KeystoreVersion, Decrypt: "ok", Confirmed: true, ConfirmedTrustRootsDigest: &digest, TrialSign: "pending"}
	if err := env.API.ReportChecks(ctx, []CheckReport{report}); err != nil {
		printf(t, "  ! reporting the confirmation to the server failed (%v); `signer run` reports it within a minute\n", cleanText(err.Error(), 200))
	} else {
		printf(t, "  ✓ reported to the server; `signer run` performs the trial signature next\n")
	}
	return nil
}

// validateServerItem 严格校验服务端下发的一项；返回校验过的信任根（服务端没有时为 nil）。
func validateServerItem(item CheckItem) (*trustroots.Roots, error) {
	switch {
	case item.KeystoreVersion < 0:
		return nil, errors.New("keystoreVersion")
	case !ident.ValidPackageName(item.PackageName):
		return nil, errors.New("packageName")
	case !fingerprint.Valid(item.CertificateSHA256):
		return nil, errors.New("certificateSha256")
	case !ident.ValidKeyAlias(item.KeyAlias):
		return nil, errors.New("keyAlias")
	case item.Box.ValidateShape() != nil:
		return nil, errors.New("box")
	}
	if item.TrustRoots == nil {
		if item.TrustRootsDigest != nil {
			return nil, errors.New("trustRootsDigest without trustRoots")
		}
		return nil, nil
	}
	normalized, err := item.TrustRoots.Normalize()
	if err != nil || !trustroots.Equal(normalized, *item.TrustRoots) {
		return nil, errors.New("trustRoots")
	}
	digest, _ := trustroots.Digest(normalized)
	if item.TrustRootsDigest == nil || *item.TrustRootsDigest != digest {
		return nil, errors.New("trustRootsDigest")
	}
	return &normalized, nil
}

func serverRootsField(r *trustroots.Roots, field string) string {
	if r == nil {
		return ""
	}
	switch field {
	case "api":
		return r.APIBaseURL
	case "ota":
		return r.OTACertificateSHA256
	case "address":
		return r.BootstrapSignerAddress
	case "hosts":
		return strings.Join(r.AppLinksHosts, ",")
	case "scheme":
		return r.Scheme
	case "channel":
		return r.DistributionChannel
	case "appId":
		return r.ApplicationID
	}
	return ""
}

// validRootsProbe 是一份合法的信任根，用来单独校验某一项的格式。
func validRootsProbe() trustroots.Roots {
	return trustroots.Roots{
		APIBaseURL: "https://api.example.com", OTACertificateSHA256: strings.Repeat("0", 64),
		BootstrapSignerAddress: "0x" + strings.Repeat("0", 40), AppLinksHosts: []string{"api.example.com"},
		Scheme: "example", DistributionChannel: "direct", ApplicationID: "example",
	}
}

func askNormalized(t Terminal, prompt string, normalize func(string) (string, bool)) (string, error) {
	var out string
	_, err := ask(t, prompt, func(s string) error {
		v, ok := normalize(s)
		if !ok {
			return errors.New("the value has the wrong format")
		}
		out = v
		return nil
	})
	return out, err
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
