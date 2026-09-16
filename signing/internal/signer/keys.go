package signer

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
	"github.com/Helix2010/RN-Server/signing/internal/securefs"
	"github.com/Helix2010/RN-Server/signing/records"
)

// 状态目录里的文件名。
const (
	x25519KeyFile  = "x25519.key"  // 32 字节 X25519 私钥：解密钥密文
	ed25519KeyFile = "ed25519.key" // 32 字节 Ed25519 种子：本机记录签名、换公钥证明
	initMarkerFile = "init.incomplete"
	runLockFile    = "run.lock"
	workDirName    = "work"
)

// MachineKeys 是签名闸的两把本机私钥。格式化输出只有公钥指纹。
type MachineKeys struct {
	X25519  *ecdh.PrivateKey
	Ed25519 ed25519.PrivateKey
}

// X25519PublicKey 返回 32 字节公钥。
func (k MachineKeys) X25519PublicKey() []byte { return k.X25519.PublicKey().Bytes() }

// Ed25519PublicKey 返回 32 字节公钥。
func (k MachineKeys) Ed25519PublicKey() ed25519.PublicKey {
	return k.Ed25519.Public().(ed25519.PublicKey)
}

// X25519SHA256 是收件人指纹（pin 文件、Box 用）。
func (k MachineKeys) X25519SHA256() string { return fingerprint.SHA256Hex(k.X25519PublicKey()) }

// Ed25519SHA256 是记录签名公钥指纹。
func (k MachineKeys) Ed25519SHA256() string { return fingerprint.SHA256Hex(k.Ed25519PublicKey()) }

func (k MachineKeys) String() string {
	if k.X25519 == nil || k.Ed25519 == nil {
		return "signer.MachineKeys{(unloaded)}"
	}
	return fmt.Sprintf("signer.MachineKeys{x25519Sha256=%s ed25519Sha256=%s private=[redacted]}", k.X25519SHA256(), k.Ed25519SHA256())
}

// GoString 覆盖 %#v。
func (k MachineKeys) GoString() string { return k.String() }

// Format 覆盖全部动词。
func (k MachineKeys) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }

// LogValue 覆盖 slog。
func (k MachineKeys) LogValue() slog.Value { return slog.StringValue(k.String()) }

// MarshalJSON 拒绝序列化。
func (k MachineKeys) MarshalJSON() ([]byte, error) {
	return nil, errors.New("signer: refusing to JSON-encode machine keys")
}

// LoadKeys 只读地加载本机私钥（show-key、confirm 等运维命令用）。
func LoadKeys(stateDir string) (MachineKeys, error) {
	if err := securefs.CheckPrivateDir(stateDir); err != nil {
		return MachineKeys{}, fmt.Errorf("state directory: %w", err)
	}
	if _, err := os.Lstat(filepath.Join(stateDir, initMarkerFile)); err == nil {
		return MachineKeys{}, errors.New("this signing gate's first start did not finish; start `signer run` again")
	}
	xRaw, err := securefs.ReadPrivateFile(filepath.Join(stateDir, x25519KeyFile), 64)
	if errors.Is(err, fs.ErrNotExist) {
		return MachineKeys{}, errors.New("this signing gate has no machine keys yet: start `signer run` once to generate them")
	}
	if err != nil {
		return MachineKeys{}, err
	}
	edRaw, err := securefs.ReadPrivateFile(filepath.Join(stateDir, ed25519KeyFile), 64)
	if err != nil {
		return MachineKeys{}, err
	}
	if len(xRaw) != 32 || len(edRaw) != ed25519.SeedSize {
		return MachineKeys{}, errors.New("machine key files have the wrong length")
	}
	x, err := ecdh.X25519().NewPrivateKey(xRaw)
	if err != nil {
		return MachineKeys{}, fmt.Errorf("x25519 key: %w", err)
	}
	return MachineKeys{X25519: x, Ed25519: ed25519.NewKeyFromSeed(edRaw)}, nil
}

// InitState 是 signer run 首次启动时的初始化：生成两把私钥（0600）并写两份记录文件的
// genesis。已经初始化过就只加载。
//
// 半途崩溃留下 init.incomplete 标记：此时私钥还没登记给任何人、记录里也没有任何签名，
// 清掉重来是安全的。没有标记却只存在一部分文件，说明状态目录被人动过，拒绝启动。
func InitState(stateDir, machineName string) (MachineKeys, bool, error) {
	if err := securefs.CheckPrivateDir(stateDir); err != nil {
		return MachineKeys{}, false, fmt.Errorf("state directory: %w", err)
	}
	marker := filepath.Join(stateDir, initMarkerFile)
	parts := []string{x25519KeyFile, ed25519KeyFile, records.TrustFileName, records.SignedFileName}
	if _, err := os.Lstat(marker); err == nil {
		for _, name := range parts {
			if err := os.Remove(filepath.Join(stateDir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return MachineKeys{}, false, err
			}
		}
		if err := os.Remove(marker); err != nil {
			return MachineKeys{}, false, err
		}
	}
	present := 0
	for _, name := range parts {
		if _, err := os.Lstat(filepath.Join(stateDir, name)); err == nil {
			present++
		} else if !errors.Is(err, fs.ErrNotExist) {
			return MachineKeys{}, false, err
		}
	}
	switch present {
	case len(parts):
		keys, err := LoadKeys(stateDir)
		return keys, false, err
	case 0:
	default:
		return MachineKeys{}, false, fmt.Errorf("state directory %s is inconsistent: only some of %v exist. Machine keys and local records belong together; if the records are lost this machine must be treated as a new signing gate", stateDir, parts)
	}

	if err := securefs.WriteFileExclusive(marker, []byte("initializing\n")); err != nil {
		return MachineKeys{}, false, err
	}
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return MachineKeys{}, false, err
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return MachineKeys{}, false, err
	}
	keys := MachineKeys{X25519: x, Ed25519: ed}
	if err := securefs.WriteFileExclusive(filepath.Join(stateDir, x25519KeyFile), x.Bytes()); err != nil {
		return MachineKeys{}, false, err
	}
	if err := securefs.WriteFileExclusive(filepath.Join(stateDir, ed25519KeyFile), ed.Seed()); err != nil {
		return MachineKeys{}, false, err
	}
	if err := records.Init(stateDir, records.GenesisParams{MachineName: machineName, Ed25519PrivateKey: ed, X25519PublicKeySHA256: keys.X25519SHA256()}); err != nil {
		return MachineKeys{}, false, err
	}
	if err := os.Remove(marker); err != nil {
		return MachineKeys{}, false, err
	}
	if err := securefs.SyncDir(stateDir); err != nil {
		return MachineKeys{}, false, err
	}
	return keys, true, nil
}

// OpenRecords 加载私钥并打开、校验本机记录；记录的 genesis 必须是这台机器、这个名字。
func OpenRecords(stateDir, machineName string) (MachineKeys, *records.Store, error) {
	keys, err := LoadKeys(stateDir)
	if err != nil {
		return MachineKeys{}, nil, err
	}
	store, err := records.Open(stateDir, keys.Ed25519)
	if err != nil {
		return MachineKeys{}, nil, err
	}
	g := store.Genesis()
	if g.X25519PublicKeySHA256 != keys.X25519SHA256() {
		store.Close()
		return MachineKeys{}, nil, errors.New("local records name a different X25519 key than the one in the state directory")
	}
	if g.MachineName != machineName {
		store.Close()
		return MachineKeys{}, nil, fmt.Errorf("local records belong to machine %q, but %s is %q", g.MachineName, EnvName, machineName)
	}
	return keys, store, nil
}
