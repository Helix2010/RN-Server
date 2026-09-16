package signer

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/ident"
	"github.com/Helix2010/RN-Server/signing/records"
	"github.com/Helix2010/RN-Server/signing/recovery"
)

// ---- 本机信任列表（上报给服务端，只作控制台提示）----

// LocalTrust 汇总本机记录里的信任：签名闸（本机在第一项）、构建机、恢复公钥指纹。
func LocalTrust(keys MachineKeys, store *records.Store) (TrustReport, error) {
	out := TrustReport{
		Signers:      []TrustedSignerReport{{Name: store.Genesis().MachineName, X25519SHA256: keys.X25519SHA256(), Ed25519SHA256: keys.Ed25519SHA256()}},
		Builders:     []TrustedBuilderReport{},
		RecoveryKeys: []string{},
	}
	peers, err := store.TrustedPeers()
	if err != nil {
		return TrustReport{}, err
	}
	for _, p := range peers {
		out.Signers = append(out.Signers, TrustedSignerReport{Name: p.Name, X25519SHA256: p.X25519PublicKeySHA256, Ed25519SHA256: p.Ed25519PublicKeySHA256})
	}
	builders, err := store.TrustedBuilders()
	if err != nil {
		return TrustReport{}, err
	}
	for _, b := range builders {
		out.Builders = append(out.Builders, TrustedBuilderReport{BuilderID: b.BuilderID, Ed25519SHA256: b.Ed25519PublicKeySHA256})
	}
	keysList, err := store.TrustedRecoveryKeys()
	if err != nil {
		return TrustReport{}, err
	}
	for _, k := range keysList {
		out.RecoveryKeys = append(out.RecoveryKeys, k.X25519PublicKeySHA256)
	}
	return out, nil
}

// ---- 服务端视图的严格校验（不合格的项不显示、不使用）----

// verifiedSigner 是校验过公钥与指纹一致的服务端签名闸。
type verifiedSigner struct {
	PeerSigner
	X25519  []byte
	Ed25519 ed25519.PublicKey
}

func verifyPeerSigner(p PeerSigner) (verifiedSigner, error) {
	switch {
	case !ident.ValidServerID(p.MachineID):
		return verifiedSigner{}, errors.New("machineId")
	case !ident.ValidMachineName(p.Name):
		return verifiedSigner{}, errors.New("name")
	case p.Status != "active":
		return verifiedSigner{}, errors.New("status")
	case p.SignerRole != nil && *p.SignerRole != "primary" && *p.SignerRole != "standby":
		return verifiedSigner{}, errors.New("signerRole")
	}
	x, err := recovery.DecodePublicKey(p.X25519PublicKey)
	if err != nil || fingerprint.SHA256Hex(x) != p.X25519PublicKeySHA256 {
		return verifiedSigner{}, errors.New("x25519PublicKey")
	}
	ed, err := base64.StdEncoding.Strict().DecodeString(p.Ed25519PublicKey)
	if err != nil || len(ed) != ed25519.PublicKeySize || fingerprint.SHA256Hex(ed) != p.Ed25519PublicKeySHA256 {
		return verifiedSigner{}, errors.New("ed25519PublicKey")
	}
	return verifiedSigner{PeerSigner: p, X25519: x, Ed25519: ed}, nil
}

func verifyPeerBuilder(b PeerBuilder) error {
	switch {
	case !ident.ValidServerID(b.MachineID):
		return errors.New("machineId")
	case !ident.ValidMachineName(b.Name):
		return errors.New("name")
	case b.Status != "active":
		return errors.New("status")
	}
	pub, err := base64.StdEncoding.Strict().DecodeString(b.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || fingerprint.SHA256Hex(pub) != b.PublicKeySHA256 {
		return errors.New("publicKey")
	}
	return nil
}

func verifyPeerRecoveryKey(k PeerRecoveryKey) ([]byte, error) {
	if !recovery.ValidName(k.Name) {
		return nil, errors.New("name")
	}
	pub, err := recovery.DecodePublicKey(k.X25519PublicKey)
	if err != nil || fingerprint.SHA256Hex(pub) != k.X25519PublicKeySHA256 {
		return nil, errors.New("x25519PublicKey")
	}
	return pub, nil
}

// ---- trust-peer ----

// TrustPeer 信任另一台签名闸：从服务端取它已接受的公钥（只显示机器信息，不先显示指纹），运维粘贴
// 那台机器安装输出里的完整 X25519 与 Ed25519 指纹，与服务端一致才写入。主签名闸从此把新密钥加密给它；
// 备签名闸从此接受它签过生成签名的密钥。
func TrustPeer(ctx context.Context, env OperatorEnv, name string) error {
	t := env.Term
	if !ident.ValidMachineName(name) {
		return errors.New("--peer must be the signing gate's machine name (^[a-z0-9][a-z0-9-]{1,39}$)")
	}
	self := env.Store.Genesis().MachineName
	if name == self {
		return errors.New("this signing gate trusts itself implicitly; --peer names another signing gate")
	}
	peers, err := env.API.Peers(ctx)
	if err != nil {
		return fmt.Errorf("fetch the signing gates registered on the server: %w", err)
	}
	var found *verifiedSigner
	for _, p := range peers.Signers {
		if p.Name != name {
			continue
		}
		v, err := verifyPeerSigner(p)
		if err != nil {
			return fmt.Errorf("the server's record for signing gate %s is malformed (%v); refusing to use it", name, err)
		}
		if found != nil {
			return fmt.Errorf("the server lists signing gate %s more than once", name)
		}
		found = &v
	}
	if found == nil {
		return fmt.Errorf("the server has no active signing gate named %s (accept its public keys in the console first)", name)
	}
	existing, err := env.Store.TrustedPeers()
	if err != nil {
		return err
	}
	for _, p := range existing {
		if p.Name == name {
			printf(t, "  ! %s is already trusted (x25519 %s, ed25519 %s, %s at %s); writing replaces it\n", name, p.X25519PublicKeySHA256, p.Ed25519PublicKeySHA256, p.Mode, p.At)
		}
	}
	role := "(none)"
	if found.SignerRole != nil {
		role = *found.SignerRole
	}
	printf(t, "\nTrust a signing gate / 信任签名闸\n  this machine:  %s\n  peer:          %s\n  machine id:    %s\n  server role:   %s\n\n", self, name, found.MachineID, role)
	printf(t, "  Paste the fingerprints printed by that machine's install command (or `signer show-key` on it), not from the console.\n")
	operator, err := askOperator(t)
	if err != nil {
		return err
	}
	x, err := askFingerprint(t, "Paste its X25519 public key SHA-256: ")
	if err != nil {
		return err
	}
	ed, err := askFingerprint(t, "Paste its Ed25519 public key SHA-256: ")
	if err != nil {
		return err
	}
	if x != found.X25519PublicKeySHA256 || ed != found.Ed25519PublicKeySHA256 {
		return fmt.Errorf("%w: the pasted fingerprints do not match the keys the server has accepted for %s; check which machine you copied them from, and whether the console accepted the right keys", ErrAborted, name)
	}
	printf(t, "  ✓ both fingerprints match the server's accepted keys\n")
	note, err := t.ReadLine("Note (optional): ")
	if err != nil {
		return err
	}
	if err := confirmTyped(t, "Type the peer's machine name to trust it: ", name); err != nil {
		return err
	}
	if err := env.Store.TrustPeer(records.PeerTrust{Name: name, X25519PublicKeySHA256: x, Ed25519PublicKeySHA256: ed,
		Mode: records.TrustModeOperator, Operator: operator, Note: strings.TrimSpace(note)}); err != nil {
		return err
	}
	printf(t, "  ✓ %s is trusted (x25519 sha256 %s, ed25519 sha256 %s)\n", name, x, ed)
	return nil
}

// RevokePeer 撤销对一台签名闸的信任：之后生成的密钥不再加密给它，它签的生成不再被自动接受。
func RevokePeer(env OperatorEnv, name, reason string) error {
	t := env.Term
	if !ident.ValidMachineName(name) {
		return errors.New("--peer is malformed")
	}
	if !records.ValidReason(reason) {
		return errors.New("--reason must be 3-512 characters without control characters")
	}
	operator, err := askOperator(t)
	if err != nil {
		return err
	}
	if err := confirmTyped(t, "Type the peer's machine name to revoke it: ", name); err != nil {
		return err
	}
	if err := env.Store.RevokePeer(name, operator, reason); err != nil {
		return err
	}
	printf(t, "  ✓ %s is no longer trusted\n", name)
	return nil
}

// ---- trust-recovery ----

// TrustRecovery 信任一把离线恢复公钥：运维粘贴密码管理器里的完整 sha256，程序从服务端找到这把公钥、
// 核对指纹后写入。之后生成的密钥加密给它。
func TrustRecovery(ctx context.Context, env OperatorEnv) error {
	t := env.Term
	printf(t, "\nTrust an offline recovery key / 信任离线恢复公钥\n  Paste the recovery public key SHA-256 from the password manager, not from the console.\n\n")
	operator, err := askOperator(t)
	if err != nil {
		return err
	}
	sha, err := askFingerprint(t, "Paste the recovery public key SHA-256: ")
	if err != nil {
		return err
	}
	peers, err := env.API.Peers(ctx)
	if err != nil {
		return fmt.Errorf("fetch the recovery keys registered on the server: %w", err)
	}
	var found *PeerRecoveryKey
	for i, k := range peers.RecoveryKeys {
		if k.X25519PublicKeySHA256 != sha {
			continue
		}
		if _, err := verifyPeerRecoveryKey(k); err != nil {
			return fmt.Errorf("the server's record for this recovery key is malformed (%v); refusing to use it", err)
		}
		found = &peers.RecoveryKeys[i]
	}
	switch {
	case found == nil:
		return fmt.Errorf("%w: the server has no recovery key with that SHA-256; register recovery-public.json in the console first, and check the pasted value", ErrAborted)
	case found.Revoked:
		return fmt.Errorf("%w: that recovery key is revoked on the server", ErrAborted)
	}
	printf(t, "  ✓ the server has this recovery key: %s\n", found.Name)
	note, err := t.ReadLine("Note (optional): ")
	if err != nil {
		return err
	}
	if err := confirmTyped(t, "Type the recovery key name to trust it: ", found.Name); err != nil {
		return err
	}
	if err := env.Store.TrustRecovery(records.RecoveryTrust{Name: found.Name, X25519PublicKeySHA256: sha, Mode: records.TrustModeOperator,
		Operator: operator, Note: strings.TrimSpace(note)}); err != nil {
		return err
	}
	printf(t, "  ✓ recovery key %s is trusted (sha256 %s); keys generated from now on are also encrypted to it\n", found.Name, sha)
	return nil
}

// RevokeRecovery 撤销对一把恢复公钥的信任。
func RevokeRecovery(env OperatorEnv, sha, reason string) error {
	t := env.Term
	v, ok := fingerprint.Normalize(sha)
	if !ok {
		return errors.New("--recovery-sha256 must be a full 64-character hex SHA-256")
	}
	if !records.ValidReason(reason) {
		return errors.New("--reason must be 3-512 characters without control characters")
	}
	operator, err := askOperator(t)
	if err != nil {
		return err
	}
	again, err := askFingerprint(t, "Paste the recovery key SHA-256 again to revoke it: ")
	if err != nil {
		return err
	}
	if again != v {
		return ErrAborted
	}
	if err := env.Store.RevokeRecovery(v, operator, reason); err != nil {
		return err
	}
	printf(t, "  ✓ recovery key %s is no longer trusted\n", v)
	return nil
}

// ---- trust-builder --builder <机器名> ----

// TrustBuilderByName 按机器名信任构建机：机器 id 与公钥从服务端取来显示（不先显示指纹），运维粘贴构建机
// 安装输出里的出处公钥 sha256，与服务端一致才写入。
func TrustBuilderByName(ctx context.Context, env OperatorEnv, name string) error {
	t := env.Term
	if !ident.ValidMachineName(name) {
		return errors.New("--builder must be the builder's machine name (^[a-z0-9][a-z0-9-]{1,39}$)")
	}
	peers, err := env.API.Peers(ctx)
	if err != nil {
		return fmt.Errorf("fetch the builders registered on the server: %w", err)
	}
	var found *PeerBuilder
	for i, b := range peers.Builders {
		if b.Name != name {
			continue
		}
		if err := verifyPeerBuilder(b); err != nil {
			return fmt.Errorf("the server's record for builder %s is malformed (%v); refusing to use it", name, err)
		}
		if found != nil {
			return fmt.Errorf("the server lists builder %s more than once", name)
		}
		found = &peers.Builders[i]
	}
	if found == nil {
		return fmt.Errorf("the server has no active builder named %s (accept its public key in the console first)", name)
	}
	builders, err := env.Store.TrustedBuilders()
	if err != nil {
		return err
	}
	for _, b := range builders {
		if b.BuilderID == found.MachineID {
			printf(t, "  ! builder %s is already trusted with ed25519 sha256 %s; writing replaces it\n", b.BuilderID, b.Ed25519PublicKeySHA256)
		}
	}
	printf(t, "\nTrust a builder / 信任构建机\n  name:       %s\n  builder id: %s (from the server)\n\n", name, found.MachineID)
	operator, err := askOperator(t)
	if err != nil {
		return err
	}
	pasted, err := askFingerprint(t, "Paste the builder's provenance public key SHA-256 (from its install output or `build-agent show-key`): ")
	if err != nil {
		return err
	}
	if pasted != found.PublicKeySHA256 {
		return fmt.Errorf("%w: the pasted fingerprint does not match the key the server has accepted for %s", ErrAborted, name)
	}
	note, err := t.ReadLine("Note (optional): ")
	if err != nil {
		return err
	}
	if err := confirmTyped(t, "Type the builder's machine name to trust it: ", name); err != nil {
		return err
	}
	if err := env.Store.TrustBuilder(records.BuilderTrust{BuilderID: found.MachineID, Ed25519PublicKeySHA256: pasted, Name: name,
		Operator: operator, Note: strings.TrimSpace(note)}); err != nil {
		return err
	}
	printf(t, "  ✓ builder %s (%s) is trusted (ed25519 sha256 %s)\n", name, found.MachineID, pasted)
	return nil
}
