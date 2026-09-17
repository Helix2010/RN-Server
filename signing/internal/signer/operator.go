package signer

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/pins"
	"github.com/Helix2010/RN-Server/signing/records"
)

func askOperator(t Terminal) (string, error) {
	return ask(t, "Your operator name: ", func(s string) error {
		if !records.ValidOperator(s) {
			return errors.New("use letters, digits, . _ @ - (at most 64)")
		}
		return nil
	})
}

func askFingerprint(t Terminal, prompt string) (string, error) {
	line, err := t.ReadLine(prompt)
	if err != nil {
		return "", err
	}
	v, ok := fingerprint.Normalize(strings.TrimSpace(line))
	if !ok {
		return "", fmt.Errorf("%w: expected a full 64-character hex SHA-256", ErrAborted)
	}
	return v, nil
}

// TrustBuilder 写入一台受信构建机：运维在构建机上执行 build-agent show-key 取得出处公钥的
// 完整 sha256，到这里粘贴两次（防止粘错）后写入。服务端登记了谁都不算数。
func TrustBuilder(env OperatorEnv, builderID, name string) error {
	t := env.Term
	if !ident.ValidServerID(builderID) {
		return errors.New("--builder-id must be the builder's machine id from the console (e.g. mch_…)")
	}
	if !ident.ValidMachineName(name) {
		return errors.New("--name must match ^[a-z0-9][a-z0-9-]{1,39}$")
	}
	builders, err := env.Store.TrustedBuilders()
	if err != nil {
		return err
	}
	for _, b := range builders {
		if b.BuilderID == builderID {
			printf(t, "  ! builder %s is already trusted with ed25519 sha256 %s; writing replaces it\n", builderID, b.Ed25519PublicKeySHA256)
		}
	}
	printf(t, "\nTrust a builder / 信任构建机\n  builder id: %s\n  name:       %s\n\n", builderID, name)
	operator, err := askOperator(t)
	if err != nil {
		return err
	}
	first, err := askFingerprint(t, "Paste the builder's provenance public key SHA-256 (from `build-agent show-key` on that machine): ")
	if err != nil {
		return err
	}
	second, err := askFingerprint(t, "Paste it again: ")
	if err != nil {
		return err
	}
	if first != second {
		return fmt.Errorf("%w: the two pasted fingerprints differ", ErrAborted)
	}
	note, err := t.ReadLine("Note (optional, e.g. where you read the fingerprint): ")
	if err != nil {
		return err
	}
	note = strings.TrimSpace(note)
	if err := confirmTyped(t, "Type the builder id to trust it: ", builderID); err != nil {
		return err
	}
	if err := env.Store.TrustBuilder(records.BuilderTrust{BuilderID: builderID, Ed25519PublicKeySHA256: first, Name: name, Operator: operator, Note: note}); err != nil {
		return err
	}
	printf(t, "  ✓ builder %s is trusted (ed25519 sha256 %s)\n", builderID, first)
	return nil
}

// RevokeBuilder 撤销对一台构建机的信任。此后它交付的包一律拒签。
func RevokeBuilder(env OperatorEnv, builderID, reason string) error {
	t := env.Term
	if !ident.ValidServerID(builderID) {
		return errors.New("--builder-id is malformed")
	}
	if !records.ValidReason(reason) {
		return errors.New("--reason must be 3-512 characters without control characters")
	}
	operator, err := askOperator(t)
	if err != nil {
		return err
	}
	if err := confirmTyped(t, "Type the builder id to revoke it: ", builderID); err != nil {
		return err
	}
	if err := env.Store.RevokeBuilder(builderID, operator, reason); err != nil {
		return err
	}
	printf(t, "  ✓ builder %s is no longer trusted\n", builderID)
	return nil
}

// PromoteMode 是提升备用的方式。
type PromoteMode int

const (
	// PromoteImport：导入旧主的 signed.jsonl（旧主状态目录还在）。
	PromoteImport PromoteMode = iota
	// PromoteManual：旧主状态目录没了，运维逐包输入已签最大 versionCode。
	PromoteManual
	// PromoteFirst：第一台主，之前没有任何主签名闸。
	PromoteFirst
)

// Promote 把本机（备）提升为主。调用前运维必须已经停掉旧主并在控制台吊销它。主只由这里产生：
// signer enroll 一律写备。
//
// 给出了旧主的 Ed25519 指纹（--import 必填，--manual 可选）时，本机受信签名闸里用这把密钥的那台（被取代的旧主）
// 与角色记录在同一次写入里撤销：旧主以后被攻破、服务端把它报成 active，新密钥也不再加密给它，它签的生成也不再
// 被接受。旧主要当备重新用，只能按新机器重装（新密钥）再 trust-peer。
func Promote(env OperatorEnv, mode PromoteMode, importPath string) error {
	t := env.Term
	role, err := env.Store.Role()
	if err != nil {
		return err
	}
	if role.Role == records.RolePrimary {
		return errors.New("this signing gate is already the primary in its local records")
	}
	name := env.Store.Genesis().MachineName
	printf(t, "\nPromote %s to primary / 提升为主签名闸\n", name)
	printf(t, "  Before continuing: stop the old primary's service and revoke it in the console.\n")
	printf(t, "  Two primaries signing at the same time can sign two different packages with the same versionCode.\n\n")
	operator, err := askOperator(t)
	if err != nil {
		return err
	}
	reason, err := ask(t, "Reason (at least 3 characters): ", func(s string) error {
		if !records.ValidReason(s) {
			return errors.New("3-512 characters without control characters")
		}
		return nil
	})
	if err != nil {
		return err
	}
	change := records.RoleChange{Role: records.RolePrimary, Operator: operator, Reason: reason}

	switch mode {
	case PromoteFirst:
		history, err := env.Store.HasSigningHistory()
		if err != nil {
			return err
		}
		if history {
			return errors.New("this signing gate already has signing records; --first is only for a signing gate that has never signed and follows no previous primary")
		}
		// 接受过别的签名闸生成的密钥，说明之前有主在签：--first 会丢掉那台主的签名记录
		confirmations, err := env.Store.Confirmations()
		if err != nil {
			return err
		}
		for _, c := range confirmations {
			if c.Mode == records.ConfirmModePeerGenerated {
				return fmt.Errorf("this signing gate accepted the keystore for %s %s generated by signing gate %s, so a primary signed before it; "+
					"--first would drop that primary's signing records: use --import (the old primary's signed.jsonl) or --manual", c.TenantSlug, c.PackageName, c.GeneratorName)
			}
		}
		change.Mode = records.RoleModeInitial
		printf(t, "  This machine becomes the first primary. Do not use this if another primary has ever signed for these tenants.\n")
		if err := confirmTyped(t, "Type this machine's name to promote it: ", name); err != nil {
			return err
		}
		if err := promoteRole(env, change); err != nil {
			return err
		}

	case PromoteImport:
		raw, err := readRegularFile(importPath, records.MaxFileSize)
		if err != nil {
			return fmt.Errorf("read the old primary's signed.jsonl: %w", err)
		}
		pinned, err := askFingerprint(t, "Paste the old primary's Ed25519 public key SHA-256 (from the offline pin file or record, or this machine's `signer list`): ")
		if err != nil {
			return err
		}
		if pinned == env.Keys.Ed25519SHA256() {
			return errors.New("that is this machine's own key; import the old primary's records")
		}
		foreign, err := records.VerifyForeignSigned(raw, pinned)
		if err != nil {
			return fmt.Errorf("the file does not verify against the pinned key: %w", err)
		}
		printf(t, "  ✓ %d lines verified, written by %s\n", foreign.Lines, foreign.Genesis.MachineName)
		// 哈希链发现不了"整行截掉文件末尾"：让运维与旧主 `signer list` 显示过的末行对一下
		printf(t, "  last line sha256 %s\n  Compare the line count and last line hash with the old primary's `signer list` output or the offline records;\n  a file cut short verifies just as well.\n", foreign.LastHash)
		printImportSummary(t, foreign)
		if err := announceSupersededPrimary(t, env.Store, pinned); err != nil {
			return err
		}
		if err := confirmTyped(t, "Type this machine's name to import these records and promote it: ", name); err != nil {
			return err
		}
		written, err := env.Store.Import(pinned, foreign.Reservations, operator)
		if err != nil {
			return err
		}
		for _, b := range foreign.Baselines {
			b.Operator = operator
			b.Note = "imported from " + foreign.Genesis.MachineName
			if err := env.Store.SetBaseline(b); err != nil {
				return err
			}
		}
		change.Mode, change.PreviousPrimaryEd25519SHA256 = records.RoleModeImportFile, pinned
		if err := promoteRole(env, change); err != nil {
			return err
		}
		printf(t, "  ✓ imported %d reservations and %d baselines\n", written, len(foreign.Baselines))

	case PromoteManual:
		confirmations, err := env.Store.Confirmations()
		if err != nil {
			return err
		}
		printf(t, "  For every package confirmed on this machine, enter the highest versionCode already signed with that certificate.\n")
		printf(t, "  Take it from the offline release records or an installed device, never from the server. Enter 0 if it was never signed.\n")
		var baselines []records.Baseline
		for _, c := range confirmations {
			view, err := env.Store.SignedState(c.PackageName, c.CertificateSHA256, "", "")
			if err != nil {
				return err
			}
			local := ""
			if view.HasMax {
				local = fmt.Sprintf(" (this machine already knows %d)", view.Max)
			}
			n, err := askInt(t, fmt.Sprintf("  %s %s / certificate %s%s: ", c.TenantSlug, c.PackageName, c.CertificateSHA256, local), 0, records.MaxVersionCode)
			if err != nil {
				return err
			}
			if n > 0 {
				baselines = append(baselines, records.Baseline{PackageName: c.PackageName, CertificateSHA256: c.CertificateSHA256, MaxVersionCode: n, Operator: operator, Note: "entered at promote"})
			}
		}
		if len(confirmations) == 0 {
			printf(t, "  No package is confirmed on this machine yet; packages confirmed later use their first-sign cap.\n")
		}
		previous, err := t.ReadLine("Old primary's Ed25519 public key SHA-256 (from the offline pin file or record, or this machine's `signer list`;\n  it revokes the old primary's trust here; press Enter to skip): ")
		if err != nil {
			return err
		}
		if previous = strings.TrimSpace(previous); previous != "" {
			v, ok := fingerprint.Normalize(previous)
			if !ok {
				return fmt.Errorf("%w: the fingerprint is not a 64-character hex SHA-256", ErrAborted)
			}
			change.PreviousPrimaryEd25519SHA256 = v
		}
		if err := announceSupersededPrimary(t, env.Store, change.PreviousPrimaryEd25519SHA256); err != nil {
			return err
		}
		if err := confirmTyped(t, "Type this machine's name to write these baselines and promote it: ", name); err != nil {
			return err
		}
		for _, b := range baselines {
			if err := env.Store.SetBaseline(b); err != nil {
				return err
			}
		}
		change.Mode = records.RoleModeManual
		if err := promoteRole(env, change); err != nil {
			return err
		}
	default:
		return errors.New("unknown promote mode")
	}
	printf(t, "  ✓ %s is now the primary in its local records. Switch the signer role in the console so the server routes jobs here.\n", name)
	return nil
}

// announceSupersededPrimary 在运维输入机器名确认之前说明：本机受信签名闸里哪台用旧主的密钥、会随提升一并撤销。
// 没给旧主指纹时不猜，列出受信签名闸与撤销命令。
func announceSupersededPrimary(t Terminal, store *records.Store, previous string) error {
	peers, err := store.TrustedPeers()
	if err != nil {
		return err
	}
	if previous == "" {
		if len(peers) > 0 {
			printf(t, "  ! No old primary fingerprint was given, so no trusted signing gate is revoked. If one of these is the old primary,\n    revoke it after promoting (otherwise new keystores stay encrypted to it and keystores it generates are still accepted):\n")
			for _, p := range peers {
				printf(t, "      signer trust-peer --revoke --peer %s --reason \"superseded by this promotion\"   (ed25519 %s)\n", p.Name, p.Ed25519PublicKeySHA256)
			}
		}
		return nil
	}
	found := false
	for _, p := range peers {
		if p.Ed25519PublicKeySHA256 == previous {
			found = true
			printf(t, "  ! Trusted signing gate %s uses the old primary's Ed25519 key: its trust is revoked together with this promotion,\n"+
				"    so new keystores are no longer encrypted to it and keystores it generates are no longer accepted.\n"+
				"    To use that machine as a standby again, reinstall it as a new machine (new keys) and run signer trust-peer for it.\n", p.Name)
		}
	}
	if !found {
		printf(t, "  (the old primary, ed25519 %s, is not among the signing gates trusted on this machine; nothing to revoke)\n", previous)
	}
	return nil
}

// promoteRole 写角色记录，并撤销被取代的旧主（records.Store.Promote）。
func promoteRole(env OperatorEnv, change records.RoleChange) error {
	revoked, err := env.Store.Promote(change)
	if err != nil {
		return err
	}
	for _, name := range revoked {
		printf(env.Term, "  ✓ %s (the old primary) is no longer trusted on this machine\n", name)
	}
	return nil
}

func printImportSummary(t Terminal, f records.Foreign) {
	type key struct{ tenant, pkg, cert string }
	type count struct{ total, open, max int64 }
	counts := map[key]count{}
	for _, r := range f.Reservations {
		k := key{r.TenantSlug, r.PackageName, r.CertificateSHA256}
		c := counts[k]
		c.total++
		if r.Status != records.StatusCompleted {
			c.open++
		}
		if r.VersionCode > c.max {
			c.max = r.VersionCode
		}
		counts[k] = c
	}
	var keys []key
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].tenant+keys[i].pkg < keys[j].tenant+keys[j].pkg })
	for _, k := range keys {
		c := counts[k]
		printf(t, "    %s %s certificate %s: %d reservations (%d not completed), highest versionCode %d\n", k.tenant, k.pkg, k.cert, c.total, c.open, c.max)
	}
	for _, b := range f.Baselines {
		printf(t, "    baseline %s certificate %s: versionCode %d\n", b.PackageName, b.CertificateSHA256, b.MaxVersionCode)
	}
	if len(keys) == 0 && len(f.Baselines) == 0 {
		printf(t, "    (no signatures recorded)\n")
	}
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("expected a regular file within the size limit")
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

// Abandon 释放一条还没有记下签名包的预留（status=reserved）。已签名、已完成的预留不能释放。
// 调用方必须持有运行锁（签名闸服务已停），否则可能与正在处理这个任务的 signer run 竞争。
func Abandon(env OperatorEnv, jobID, reason string) error {
	t := env.Term
	if !ident.ValidServerID(jobID) {
		return errors.New("--job is malformed")
	}
	if !records.ValidReason(reason) {
		return errors.New("--reason must be 3-512 characters without control characters")
	}
	list, err := env.Store.Reservations()
	if err != nil {
		return err
	}
	var found *records.Reservation
	for i := range list {
		if list[i].JobID == jobID && list[i].Status != records.StatusAbandoned {
			found = &list[i]
		}
	}
	if found == nil {
		return fmt.Errorf("this signing gate holds no open reservation for job %s", jobID)
	}
	switch found.Status {
	case records.StatusCompleted:
		return fmt.Errorf("job %s was signed and delivered (release %s); a delivered reservation cannot be released", jobID, found.ReleaseID)
	case records.StatusSigned:
		return fmt.Errorf("job %s already produced signed package %s, which may have reached the server; its versionCode stays taken — build again with a higher versionCode", jobID, found.SignedSHA256)
	}
	printf(t, "\nRelease a reservation / 释放预留\n  job:       %s\n  tenant:    %s\n  package:   %s\n  certificate: %s\n  versionCode: %d\n  unsigned sha256: %s\n  reserved at: %s\n\n",
		found.JobID, found.TenantSlug, found.PackageName, found.CertificateSHA256, found.VersionCode, found.UnsignedSHA256, found.ReservedAt)
	printf(t, "  No signed package was recorded for this reservation, so none left this machine. Releasing it lets another\n  package use this versionCode.\n\n")
	operator, err := askOperator(t)
	if err != nil {
		return err
	}
	if err := confirmTyped(t, "Type the job id to release the reservation: ", jobID); err != nil {
		return err
	}
	if _, err := env.Store.Abandon(jobID, operator, reason); err != nil {
		return err
	}
	printf(t, "  ✓ reservation released\n")
	return nil
}

// List 打印本机记录。
func List(w io.Writer, keys MachineKeys, store *records.Store) error {
	g := store.Genesis()
	role, err := store.Role()
	if err != nil {
		return err
	}
	builders, err := store.TrustedBuilders()
	if err != nil {
		return err
	}
	confirmations, err := store.Confirmations()
	if err != nil {
		return err
	}
	reservations, err := store.Reservations()
	if err != nil {
		return err
	}
	baselines, err := store.Baselines()
	if err != nil {
		return err
	}
	trustTip, signedTip, err := store.Tips()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "machine %s\n  x25519 sha256  %s\n  ed25519 sha256 %s\n", g.MachineName, keys.X25519SHA256(), keys.Ed25519SHA256())
	// 行数与末行哈希抄进离线记录：日后 promote --import 时用来发现被截短的 signed.jsonl
	fmt.Fprintf(w, "  trust.jsonl  %d lines, last line sha256 %s\n", trustTip.Lines, trustTip.LastHash)
	fmt.Fprintf(w, "  signed.jsonl %d lines, last line sha256 %s\n", signedTip.Lines, signedTip.LastHash)
	if role.Mode == "" {
		fmt.Fprintf(w, "role standby (no role record)\n")
	} else {
		fmt.Fprintf(w, "role %s (%s at %s by %s: %s)\n", role.Role, role.Mode, role.At, role.Operator, role.Reason)
	}
	fmt.Fprintf(w, "\ntrusted builders (%d)\n", len(builders))
	for _, b := range builders {
		fmt.Fprintf(w, "  %s %s ed25519 %s (at %s by %s)\n", b.BuilderID, b.Name, b.Ed25519PublicKeySHA256, b.At, b.Operator)
	}
	peers, err := store.TrustedPeers()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "\ntrusted signing gates (%d, this machine is trusted implicitly)\n", len(peers))
	for _, p := range peers {
		fmt.Fprintf(w, "  %s x25519 %s ed25519 %s (%s at %s by %s)\n", p.Name, p.X25519PublicKeySHA256, p.Ed25519PublicKeySHA256, p.Mode, p.At, p.Operator)
	}
	recoveryKeys, err := store.TrustedRecoveryKeys()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "\ntrusted recovery keys (%d)\n", len(recoveryKeys))
	for _, k := range recoveryKeys {
		fmt.Fprintf(w, "  %s sha256 %s (%s at %s by %s)\n", k.Name, k.X25519PublicKeySHA256, k.Mode, k.At, k.Operator)
	}
	fmt.Fprintf(w, "\nconfirmed tenants (%d)\n", len(confirmations))
	for _, c := range confirmations {
		r := c.TrustRoots
		fmt.Fprintf(w, "  %s %s certificate %s alias %s (at %s by %s)\n", c.TenantSlug, c.PackageName, c.CertificateSHA256, c.KeyAlias, c.ConfirmedAt, c.ConfirmedBy)
		fmt.Fprintf(w, "    apiBaseUrl %s  ota %s  bootstrap %s\n", r.APIBaseURL, r.OTACertificateSHA256, r.BootstrapSignerAddress)
		fmt.Fprintf(w, "    appLinksHosts %s  scheme %s  channel %s  applicationId %s\n", strings.Join(r.AppLinksHosts, ","), r.Scheme, r.DistributionChannel, r.ApplicationID)
		fmt.Fprintf(w, "    minSdk %d targetSdk %d firstSignCap %d digest %s\n", c.MinSDK, c.TargetSDK, c.FirstSignMaxVersionCode, c.TrustRootsDigest)
	}
	fmt.Fprintf(w, "\nsigned (%d)\n", len(reservations))
	for _, r := range reservations {
		fmt.Fprintf(w, "  %s %-9s %s %s %s vc %d unsigned %s", r.UpdatedAt, r.Status, r.JobID, r.TenantSlug, r.PackageName, r.VersionCode, r.UnsignedSHA256)
		switch r.Status {
		case records.StatusSigned:
			fmt.Fprintf(w, " signed %s", r.SignedSHA256)
		case records.StatusCompleted:
			fmt.Fprintf(w, " signed %s release %s", r.SignedSHA256, r.ReleaseID)
		}
		if r.Source == "import" {
			fmt.Fprintf(w, " (imported)")
		}
		fmt.Fprintln(w)
	}
	if len(baselines) > 0 {
		fmt.Fprintf(w, "\nbaselines (%d)\n", len(baselines))
		for _, b := range baselines {
			fmt.Fprintf(w, "  %s certificate %s max versionCode %d (at %s by %s)\n", b.PackageName, b.CertificateSHA256, b.MaxVersionCode, b.At, b.Operator)
		}
	}
	return nil
}

// ShowKey 只读地打印本机公钥与可直接粘进 pin 文件的 JSON 片段。
func ShowKey(w io.Writer, name string, keys MachineKeys, role records.Role) error {
	pinRole := pins.RoleStandby
	if role == records.RolePrimary {
		pinRole = pins.RolePrimary
	}
	entry, err := pins.Entry(name, pinRole, keys.X25519PublicKey(), keys.Ed25519PublicKey())
	if err != nil {
		return err
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "machine name:          %s\n", name)
	fmt.Fprintf(w, "role (local records):  %s\n", role)
	fmt.Fprintf(w, "X25519 public key:     %s\n", base64.StdEncoding.EncodeToString(keys.X25519PublicKey()))
	fmt.Fprintf(w, "X25519 sha256:         %s\n", keys.X25519SHA256())
	fmt.Fprintf(w, "Ed25519 public key:    %s\n", base64.StdEncoding.EncodeToString(keys.Ed25519PublicKey()))
	fmt.Fprintf(w, "Ed25519 sha256:        %s\n", keys.Ed25519SHA256())
	fmt.Fprintf(w, "\npin file entry (add it to \"signers\" in the offline pin file %s; the role there is only a label):\n%s\n", pins.Format, raw)
	return nil
}
