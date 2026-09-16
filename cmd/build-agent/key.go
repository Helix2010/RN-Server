package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Helix2010/RN-Server/signing/fingerprint"
)

// 出处签名密钥：这台构建机的身份。
//
// 控制进程用它给出处声明签名；签名闸只认在本机 pin 过（signer trust-builder）的公钥 sha256。
// 私钥只在状态目录里（0700 目录、0600 文件），执行进程是另一个用户，读不到。
//
// 丢了它不需要恢复：按新机器处理（控制台新建机器发新令牌，签名闸上重新 trust-builder）。
const (
	provenanceKeyFile     = "provenance-ed25519.key"
	provenanceNextKeyFile = "provenance-ed25519.next.key"
)

// machineKey 是一把出处密钥。
type machineKey struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
	sha256  string
}

func newMachineKey(private ed25519.PrivateKey) machineKey {
	public := private.Public().(ed25519.PublicKey)
	return machineKey{private: private, public: public, sha256: fingerprint.SHA256Hex(public)}
}

func (k machineKey) publicBase64() string { return base64.StdEncoding.EncodeToString(k.public) }

// ensureStateDir 建出或核对状态目录：真实目录、属于本用户、组和其他人没有任何权限。
// 不合规就拒绝启动，而不是把密钥写进一个别人能读的地方。
func ensureStateDir(dir string, create bool) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) && create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return err
	}
	return checkPrivate(dir, info, true)
}

func checkPrivate(path string, info fs.FileInfo, wantDir bool) error {
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s must not be a symlink", path)
	}
	if wantDir && !info.IsDir() {
		return fmt.Errorf("%s must be a directory", path)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file", path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s must belong to the user running build-agent", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s has mode %04o; group and others must have no access (chmod %s)", path, perm, map[bool]string{true: "700", false: "600"}[wantDir])
	}
	return nil
}

// readKeyFile 读一把私钥（base64 的 32 字节种子），核对文件权限。文件不在返回 fs.ErrNotExist。
func readKeyFile(path string) (machineKey, error) {
	if _, err := os.Lstat(path); err != nil {
		return machineKey{}, err
	}
	// 打开时不跟随符号链接，权限按打开的这个文件核对，读的也是它
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return machineKey{}, fmt.Errorf("%s: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return machineKey{}, err
	}
	if err := checkPrivate(path, info, false); err != nil {
		return machineKey{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4096))
	if err != nil {
		return machineKey{}, err
	}
	seed, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return machineKey{}, fmt.Errorf("%s is not a provenance key file", path)
	}
	return newMachineKey(ed25519.NewKeyFromSeed(seed)), nil
}

// createKeyFile 生成一把新私钥，O_EXCL 一次定下 0600，不存在先宽后紧的窗口。
func createKeyFile(path string) (machineKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return machineKey{}, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return machineKey{}, err
	}
	if _, err := file.WriteString(base64.StdEncoding.EncodeToString(seed) + "\n"); err != nil {
		file.Close()
		_ = os.Remove(path)
		return machineKey{}, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(path)
		return machineKey{}, err
	}
	if err := file.Close(); err != nil {
		return machineKey{}, err
	}
	return newMachineKey(ed25519.NewKeyFromSeed(seed)), nil
}

// keyring 是当前出处密钥，以及（运维执行过 rotate-key 时）待换上的下一把。
type keyring struct {
	dir     string
	current machineKey
	next    *machineKey
}

// loadOrCreateKeyring 给常驻进程用：状态目录与当前密钥没有就建。
func loadOrCreateKeyring(dir string) (*keyring, error) {
	if err := ensureStateDir(dir, true); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, provenanceKeyFile)
	current, err := readKeyFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		current, err = createKeyFile(path)
	}
	if err != nil {
		return nil, err
	}
	ring := &keyring{dir: dir, current: current}
	next, err := readKeyFile(filepath.Join(dir, provenanceNextKeyFile))
	switch {
	case err == nil:
		ring.next = &next
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	return ring, nil
}

// readKeyringReadOnly 给 show-key 用：**只读**，什么都不建。运维拿它核对"这台机器的身份"，
// 它自己造出一把密钥就等于让核对失去意义。
func readKeyringReadOnly(dir string) (*keyring, error) {
	if err := ensureStateDir(dir, false); err != nil {
		return nil, err
	}
	current, err := readKeyFile(filepath.Join(dir, provenanceKeyFile))
	if err != nil {
		return nil, err
	}
	ring := &keyring{dir: dir, current: current}
	next, err := readKeyFile(filepath.Join(dir, provenanceNextKeyFile))
	switch {
	case err == nil:
		ring.next = &next
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	return ring, nil
}

// createNextKey 给 rotate-key 用：当前密钥必须已经存在；下一把已存在就原样返回（幂等）。
func createNextKey(dir string) (machineKey, bool, error) {
	ring, err := readKeyringReadOnly(dir)
	if err != nil {
		return machineKey{}, false, err
	}
	if ring.next != nil {
		return *ring.next, false, nil
	}
	next, err := createKeyFile(filepath.Join(dir, provenanceNextKeyFile))
	return next, true, err
}

// promoteNext 在服务端已经接受下一把公钥之后换上它。旧私钥随之删除：它已经没有用处，
// 留着只是多一份能冒充这台机器的东西。
func (r *keyring) promoteNext() error {
	if r.next == nil {
		return errors.New("no rotation key to promote")
	}
	if err := os.Rename(filepath.Join(r.dir, provenanceNextKeyFile), filepath.Join(r.dir, provenanceKeyFile)); err != nil {
		return err
	}
	r.current, r.next = *r.next, nil
	return nil
}
