package main

// install-ios-material：把控制台传下来的一份密文解开、装到这台机器上。
//
// 以**执行账户**（_rnbuilder）运行，由控制进程经 sudo 调起，密文走**标准输入**：
//
//	sudo -n -u _rnbuilder /opt/rn-build-agent/build-runner install-ios-material --signing-dir /var/rn-build-signing
//
// 密文走标准输入而不是路径：控制进程手里那份副本在它的状态目录下（0700，同一棵树里放着
// 出处私钥），给另一个账户开一条能读到那里的路，等于为了传一份不是机密的密文放宽一个装着
// 机密的目录——与 ios-upload 收 .ipa 同一个理由。
//
// 解密用的私钥在 <signing-dir>/material-key.x25519（0600，这个账户自己的），装机时由人放。
// **控制进程没有它**：它持有机器令牌与出处密钥，不该同时握着签名材料。

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
	"github.com/Helix2010/RN-Server/signing/iosmaterial"
)

// materialKeyFileName 是这个账户解材料用的私钥。装机时由人放（设计 §7）。
const materialKeyFileName = "material-key.x25519"

// securityCommand 起 `security` 子进程。测试换掉它——macOS 才有这个程序，而这一段的
// 判断逻辑在哪儿都该是对的。
var securityCommand = func(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "/usr/bin/security", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	return cmd
}

// installIOSMaterial 读密文、解开、按种类落地。回一行 JSON 给控制进程。
func installIOSMaterial(ctx context.Context, out io.Writer, in io.Reader, who identity, dir string) error {
	if err := checkSigningDir(who, dir); err != nil {
		return usageError{err}
	}
	raw, err := io.ReadAll(io.LimitReader(in, iosmaterial.MaxBoxSize+1))
	if err != nil {
		return err
	}
	box, err := iosmaterial.ParseBox(raw)
	if err != nil {
		return usageError{err}
	}
	private, err := readMaterialKey(filepath.Join(dir, materialKeyFileName))
	if err != nil {
		return err
	}
	defer wipe(private)
	material, err := iosmaterial.Open(box, private)
	if err != nil {
		return fmt.Errorf("cannot open this material: %w", err)
	}
	switch material.Kind {
	case iosmaterial.KindCertificate:
		err = importCertificate(ctx, dir, material)
	case iosmaterial.KindProfile:
		err = writeProfile(dir, material)
	default:
		// 上传 Key 是另一个账户的事（ios-upload install-key）
		err = fmt.Errorf("%s is not installed by the build user", material.Kind)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{
		"installed": true, "kind": material.Kind, "teamId": material.TeamID,
		"bundleId": material.BundleID,
	})
}

// importCertificate 把 .p12 导进签名钥匙串，并做 set-key-partition-list。
//
// 少了后面那一步，codesign 第一次用这把私钥时会弹 UI 授权，而这台机器没有图形会话——
// 构建会卡在那里直到超时，日志上看不出原因（设计 §4.2）。
func importCertificate(ctx context.Context, dir string, material iosmaterial.Material) error {
	p12, err := base64.StdEncoding.Strict().DecodeString(material.P12Base64)
	if err != nil {
		return fmt.Errorf("the certificate in this material is not base64: %w", err)
	}
	defer wipe(p12)
	keychain := filepath.Join(dir, jobspec.IOSKeychainFileName)
	if _, err := os.Stat(keychain); err != nil {
		return fmt.Errorf("no signing keychain at %s: %w", keychain, err)
	}
	keychainPassword, err := os.ReadFile(filepath.Join(dir, "rn-signing.password"))
	if err != nil {
		return fmt.Errorf("cannot read the keychain password: %w", err)
	}
	defer wipe(keychainPassword)

	// .p12 要落一次盘：security import 只收路径。0600、这个账户自己的目录、用完就删
	file, err := os.CreateTemp(dir, ".import-*.p12")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(p12); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	// -P 把 .p12 的口令放进命令行。这一条**不扩大暴露面**：导进去之后私钥就在这个账户的
	// 钥匙串里，而钥匙串口令也在这个账户读得到的文件里——能看见这条命令行的人里，真正要
	// 防的那个（跑在同一个账户下的第三方构建代码）本来就已经能用这把私钥签名了。
	// 归档里那份 .p12 的口令是每张证书现场随机生成的（运维手册 §1.2），不与别处共用。
	importCmd := securityCommand(ctx, "import", file.Name(), "-k", keychain,
		"-T", "/usr/bin/codesign", "-f", "pkcs12", "-P", material.P12Password)
	if out, err := importCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("security import: %w: %s", err, firstLine(out))
	}
	partition := securityCommand(ctx, "set-key-partition-list", "-S", "apple-tool:,apple:",
		"-s", "-k", strings.TrimRight(string(keychainPassword), "\r\n"), keychain)
	if out, err := partition.CombinedOutput(); err != nil {
		return fmt.Errorf("security set-key-partition-list: %w: %s", err, firstLine(out))
	}
	return nil
}

// writeProfile 把描述文件放到 profiles/<TEAMID>/<bundle id>.mobileprovision。
func writeProfile(dir string, material iosmaterial.Material) error {
	body, err := base64.StdEncoding.Strict().DecodeString(material.ProfileBase64)
	if err != nil {
		return fmt.Errorf("the profile in this material is not base64: %w", err)
	}
	teamDir := filepath.Join(dir, jobspec.IOSProfilesDirName, material.TeamID)
	if err := os.MkdirAll(teamDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(teamDir, material.BundleID+jobspec.IOSProfileSuffix)
	// 先写临时文件再改名：换一份描述文件的中途机器可能正在盘点，半个文件会被当成坏文件
	tmp, err := os.CreateTemp(teamDir, ".profile-*")
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

// readMaterialKey 读这个账户解材料用的私钥。它必须是这个账户自己的、别人读不到的文件。
func readMaterialKey(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("no material key at %s: it is placed at install time "+
			"(install-macos.sh --material-key-builder); without it this machine cannot open anything "+
			"the console sends", path)
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
		return nil, fmt.Errorf("%s is readable by group or others (mode %04o); "+
			"a material key must be 0600", path, info.Mode().Perm())
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

func firstLine(out []byte) string {
	line, _, _ := bytes.Cut(bytes.TrimSpace(out), []byte("\n"))
	if len(line) > 300 {
		line = line[:300]
	}
	return string(line)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
