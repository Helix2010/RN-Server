package main

// --install-key：把控制台传下来的一份上传 Key 密文解开、装到这台机器上。
//
// 以**上传账户**（_rnuploader）运行，由控制进程经 sudo 调起，密文走标准输入：
//
//	sudo -n -u _rnuploader /opt/rn-build-agent/ios-upload --install-key --keys /var/rn-build-upload
//
// 解密用的私钥在 <keys>/material-key.x25519（0600，这个账户自己的），装机时由人放。
// **控制进程与执行进程都没有它**：上传 Key 是那些签名材料唯一缺的出口，它只属于这个账户。

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Helix2010/RN-Server/internal/ascapi"
	"github.com/Helix2010/RN-Server/signing/iosmaterial"
)

const materialKeyFileName = "material-key.x25519"

// installKey 读密文、解开、把 key.json 与 .p8 放到 <keys>/<TEAMID>/ 下。
func installKey(stdin io.Reader, stdout io.Writer, keysDir string) error {
	raw, err := io.ReadAll(io.LimitReader(stdin, iosmaterial.MaxBoxSize+1))
	if err != nil {
		return err
	}
	box, err := iosmaterial.ParseBox(raw)
	if err != nil {
		return err
	}
	if box.Kind != iosmaterial.KindUploadKey {
		return fmt.Errorf("%s is not installed by the upload account", box.Kind)
	}
	private, err := readMaterialKey(filepath.Join(keysDir, materialKeyFileName))
	if err != nil {
		return err
	}
	defer wipeBytes(private)
	material, err := iosmaterial.Open(box, private)
	if err != nil {
		return fmt.Errorf("cannot open this upload key: %w", err)
	}
	p8, err := base64.StdEncoding.Strict().DecodeString(material.P8Base64)
	if err != nil {
		return fmt.Errorf("the .p8 in this material is not base64: %w", err)
	}
	defer wipeBytes(p8)
	if !keyIDPattern.MatchString(material.KeyID) {
		return fmt.Errorf("keyId %q is malformed", material.KeyID)
	}
	// 落盘之前先解一次：装上一把用不了的 Key，发现它要等到第一次真去传包——那时候构建
	// 已经跑完两小时，而报错指向的是上传，不是这次安装
	if _, err := ascapi.ParsePrivateKey(string(p8)); err != nil {
		return fmt.Errorf("the .p8 in this material is not a usable App Store Connect private key: %w", err)
	}

	teamDir := filepath.Join(keysDir, material.TeamID)
	if err := os.MkdirAll(teamDir, 0o700); err != nil {
		return err
	}
	meta, err := json.Marshal(map[string]string{
		"issuerId": material.IssuerID, "keyId": material.KeyID,
	})
	if err != nil {
		return err
	}
	// 先写 .p8 再写 key.json：读的那一侧按 key.json 找文件名，反过来的话中途有一瞬间
	// key.json 指着一个还不存在的 .p8
	if err := writePrivate(filepath.Join(teamDir, "AuthKey_"+material.KeyID+".p8"), p8); err != nil {
		return err
	}
	if err := writePrivate(filepath.Join(teamDir, "key.json"), append(meta, '\n')); err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(map[string]any{
		"installed": true, "kind": material.Kind, "teamId": material.TeamID, "keyId": material.KeyID,
	})
}

// materialKeyFingerprint 打印本机这把材料私钥对应的**公钥**指纹，装机时与控制台核对。
func materialKeyFingerprint(stdout io.Writer, keysDir string) error {
	private, err := readMaterialKey(filepath.Join(keysDir, materialKeyFileName))
	if err != nil {
		return err
	}
	defer wipeBytes(private)
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return fmt.Errorf("%s is not a usable X25519 private key: %w", materialKeyFileName, err)
	}
	digest := sha256.Sum256(key.PublicKey().Bytes())
	fmt.Fprintln(stdout, hex.EncodeToString(digest[:]))
	return nil
}

// writePrivate 以 0600 原子写一个文件。
func writePrivate(path string, body []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".install-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// readMaterialKey 读这个账户解材料用的私钥。别人读得到就不是它了。
func readMaterialKey(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("no material key at %s: it is placed at install time "+
			"(install-macos.sh --material-key-uploader)", path)
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	switch {
	case err != nil:
		return nil, err
	case !info.Mode().IsRegular():
		return nil, fmt.Errorf("%s is not a regular file", path)
	case info.Mode().Perm()&0o077 != 0:
		return nil, fmt.Errorf("%s is readable by group or others (mode %04o); it must be 0600",
			path, info.Mode().Perm())
	}
	raw, err := io.ReadAll(io.LimitReader(file, 1<<10))
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%s is not a base64 X25519 private key", path)
	}
	return key, nil
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
