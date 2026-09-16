package signer

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Helix2010/RN-Server/signing/internal/securefs"
	"github.com/Helix2010/RN-Server/signing/keystorebox"
	"github.com/Helix2010/RN-Server/signing/pkcs12"
)

// expectedIdentity 是本机确认值（签名时）或服务端记录（试解时）里的身份。
type expectedIdentity struct {
	TenantSlug        string
	PackageName       string
	CertificateSHA256 string
}

// keystoreMaterial 是解开并核对过的签名密钥。只在内存里、只在签名前后短暂存在。
type keystoreMaterial struct {
	Plain keystorebox.Plaintext
	P12   []byte
}

func (m keystoreMaterial) String() string { return "signer.keystoreMaterial{[redacted]}" }

// keystoreError 区分"解不开 / 内容不对"的原因，调用方据此决定违规码。
type keystoreError struct {
	Code string
	Msg  string
}

func (e *keystoreError) Error() string { return e.Msg }

// openKeystore 用本机私钥解开 Box，逐项比对租户、包名、证书指纹，并用口令打开 PKCS#12、
// 确认恰好一把私钥、别名是密文里的别名、证书指纹与期望一致（自己算，不信密文里写的）。
func openKeystore(box keystorebox.Box, keys MachineKeys, want expectedIdentity) (keystoreMaterial, error) {
	plain, err := keystorebox.Open(box, keys.X25519.Bytes())
	switch {
	case errors.Is(err, keystorebox.ErrNotAddressedToThisKey):
		return keystoreMaterial{}, &keystoreError{Code: "KEYSTORE_NOT_FOR_THIS_SIGNER", Msg: "the keystore box is addressed to a different signing gate key"}
	case err != nil:
		return keystoreMaterial{}, &keystoreError{Code: "KEYSTORE_DECRYPT_FAILED", Msg: "the keystore box does not open with this signing gate's key: " + err.Error()}
	}
	if plain.TenantSlug != want.TenantSlug || plain.PackageName != want.PackageName || plain.CertificateSHA256 != want.CertificateSHA256 {
		return keystoreMaterial{}, &keystoreError{Code: "KEYSTORE_IDENTITY_MISMATCH", Msg: "the decrypted keystore is bound to a different tenant, package or certificate than expected"}
	}
	p12, err := plain.P12()
	if err != nil {
		return keystoreMaterial{}, &keystoreError{Code: "KEYSTORE_UNUSABLE", Msg: "the decrypted keystore has no usable PKCS#12 file"}
	}
	if plain.StorePassword != plain.KeyPassword {
		// PKCS#12 在 Java 里只有一个口令；两个不同的口令说明原件不是离线工具产出的
		return keystoreMaterial{}, &keystoreError{Code: "KEYSTORE_UNUSABLE", Msg: "the keystore store and key passwords differ, which PKCS#12 keystores do not support"}
	}
	entry, err := pkcs12.FindKey(p12, plain.StorePassword, plain.KeyAlias)
	if err != nil {
		return keystoreMaterial{}, &keystoreError{Code: "KEYSTORE_UNUSABLE", Msg: "the decrypted PKCS#12 file does not open with its password and alias: " + err.Error()}
	}
	if got := pkcs12.CertificateSHA256(entry); got != want.CertificateSHA256 {
		return keystoreMaterial{}, &keystoreError{Code: "KEYSTORE_IDENTITY_MISMATCH", Msg: fmt.Sprintf("the PKCS#12 certificate sha256 is %s, not the expected %s", got, want.CertificateSHA256)}
	}
	return keystoreMaterial{Plain: plain, P12: p12}, nil
}

// runtimeFiles 是写进 SIGNER_RUNTIME_DIR（tmpfs）的明文 keystore 与口令文件。
type runtimeFiles struct {
	Dir               string
	KeystorePath      string
	StorePasswordFile string
	KeyPasswordFile   string
}

// writeRuntimeFiles 在运行时目录下建一个 0700 的子目录，写 keystore 与两个口令文件（0600）。
//
// 两个口令必须是两个文件：--ks-pass 与 --key-pass 指向同一个文件时，apksigner 把它当成一个
// 流依次读两行，第二行读不到就报 "end of file reached"（apksigner 35.0.0 实测）。
func writeRuntimeFiles(runtimeDir string, m keystoreMaterial) (runtimeFiles, error) {
	if err := securefs.CheckPrivateDir(runtimeDir); err != nil {
		return runtimeFiles{}, fmt.Errorf("runtime directory: %w", err)
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return runtimeFiles{}, err
	}
	dir := filepath.Join(runtimeDir, "sign-"+hex.EncodeToString(suffix))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return runtimeFiles{}, err
	}
	f := runtimeFiles{
		Dir:               dir,
		KeystorePath:      filepath.Join(dir, "keystore.p12"),
		StorePasswordFile: filepath.Join(dir, "store.pass"),
		KeyPasswordFile:   filepath.Join(dir, "key.pass"),
	}
	for path, data := range map[string][]byte{
		f.KeystorePath:      m.P12,
		f.StorePasswordFile: []byte(m.Plain.StorePassword + "\n"),
		f.KeyPasswordFile:   []byte(m.Plain.KeyPassword + "\n"),
	} {
		if err := securefs.WriteFileExclusive(path, data); err != nil {
			_ = f.Remove()
			return runtimeFiles{}, err
		}
	}
	return f, nil
}

// Remove 删掉这次签名的明文文件与子目录。
func (f runtimeFiles) Remove() error {
	if f.Dir == "" {
		return nil
	}
	return os.RemoveAll(f.Dir)
}
