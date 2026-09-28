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
	"sort"
	"strings"
	"syscall"

	"errors"
	"github.com/Helix2010/RN-Server/internal/ascapi"
	"github.com/Helix2010/RN-Server/signing/iosmaterial"
	"io/fs"
)

const materialKeyFileName = "material-key.x25519"

// rejectedPrefix 标出「材料本身不合格」，与 build-runner 同一个约定：控制进程认出它，同一版不再
// 反复试（设计 ios-tenant-owned-signing-material-2026-09-25 §12.2）。
const rejectedPrefix = "rejected: "

// tenantsDirName 是按租户落盘的那一层：<keys>/tenants/<租户>/<TEAMID>/（设计 §4.1）。多这一层
// 是因为租户 id 是纯数字，也匹配 Team ID 的正则，直接放第一层会和旧布局混在一起
const tenantsDirName = "tenants"

// keyDir 是一个 Team 的上传 Key 所在的目录。tenant 为空是旧布局（每 Team 一份、同 Team 的租户共用）。
// 调用方已经校验过 tenant 与 team 的形状。
func keyDir(keysDir, tenant, team string) string {
	if tenant == "" {
		return filepath.Join(keysDir, team)
	}
	return filepath.Join(keysDir, tenantsDirName, tenant, team)
}

// installKey 读密文、解开、把 key.json 与 .p8 放到 keyDir 下。
//
// tenant 非空时这份材料属于那个租户：v2 的材料自己也写着租户，两者必须一致；v1（从按 Team 的旧行
// 复制过来的）只在带 legacy 时收——服务端只对标了 legacy 的清单项这样做。
func installKey(stdin io.Reader, stdout io.Writer, keysDir, tenant string, legacy bool) error {
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
	switch {
	case tenant == "" && box.Version != iosmaterial.VersionLegacy:
		// 带租户的 Key 放进旧布局，就等于交给同 Team 的所有租户
		return fmt.Errorf("this upload key belongs to tenant %s; install it with --tenant", material.TenantID)
	case tenant != "" && box.Version == iosmaterial.VersionTenant && material.TenantID != tenant:
		return fmt.Errorf("%sthis upload key belongs to tenant %s, not to tenant %s", rejectedPrefix, material.TenantID, tenant)
	case tenant != "" && box.Version == iosmaterial.VersionLegacy && !legacy:
		return fmt.Errorf("%sthis is a version 1 upload key with no tenant in it; only a slot the server marks legacy may hold one", rejectedPrefix)
	}
	p8, err := base64.StdEncoding.Strict().DecodeString(material.P8Base64)
	if err != nil {
		return fmt.Errorf("%sthe .p8 in this material is not base64: %w", rejectedPrefix, err)
	}
	defer wipeBytes(p8)
	if !keyIDPattern.MatchString(material.KeyID) {
		return fmt.Errorf("%skeyId %q is malformed", rejectedPrefix, material.KeyID)
	}
	// 落盘之前先解一次：装上一把用不了的 Key，发现它要等到第一次真去传包——那时候构建
	// 已经跑完两小时，而报错指向的是上传，不是这次安装
	if _, err := ascapi.ParsePrivateKey(string(p8)); err != nil {
		return fmt.Errorf("%sthe .p8 in this material is not a usable App Store Connect private key: %w", rejectedPrefix, err)
	}

	teamDir := keyDir(keysDir, tenant, material.TeamID)
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
	result := map[string]any{
		"installed": true, "kind": material.Kind, "teamId": material.TeamID, "keyId": material.KeyID,
	}
	if tenant != "" {
		result["tenantId"] = tenant
	}
	return json.NewEncoder(stdout).Encode(result)
}

// listKeys 打印这台机器上**装好了上传 Key 的 Team**。
//
// 非有这条不可：上传区是 `/var/rn-build-upload` 0700 `_rnuploader`，而"这个 Team 能不能
// 上传"的判断在控制进程（`_rnbuildagent`）那一侧——它连这个目录都 stat 不了，自己去看
// 只会得到 EACCES，然后把每个 Team 都当成"没有上传 Key"。与签名区那次（build-runner
// ios-inventory）同一个形状：判断留在控制进程，原文由持有它的账户交出来。
//
// 只报 Team 名（旧布局在 teams，按租户的在 tenants），不报 issuer id、key id 或任何密钥内容——
// 控制进程不需要它们。
func listKeys(stdout io.Writer, keysDir string) error {
	teams, err := teamsWithKeys(keysDir)
	if err != nil {
		return fmt.Errorf("cannot read the upload key directory: %w", err)
	}
	tenants := map[string][]string{}
	root := filepath.Join(keysDir, tenantsDirName)
	entries, err := os.ReadDir(root)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("cannot read the tenants' upload keys: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !iosmaterial.ValidTenantID(entry.Name()) {
			continue
		}
		held, err := teamsWithKeys(filepath.Join(root, entry.Name()))
		if err != nil {
			return fmt.Errorf("cannot read the upload keys of tenant %s: %w", entry.Name(), err)
		}
		if len(held) > 0 {
			tenants[entry.Name()] = held
		}
	}
	return json.NewEncoder(stdout).Encode(map[string]any{"teams": teams, "tenants": tenants})
}

// teamsWithKeys 列出 dir 下装好了上传 Key 的 Team 目录。
func teamsWithKeys(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	teams := []string{}
	for _, entry := range entries {
		if !entry.IsDir() || !appleTeamIDPattern.MatchString(entry.Name()) {
			continue
		}
		// key.json 是最后写的那个文件（见 installKey），它在就说明这一格是完整的
		if _, err := os.Stat(filepath.Join(dir, entry.Name(), "key.json")); err != nil {
			continue
		}
		teams = append(teams, entry.Name())
	}
	sort.Strings(teams)
	return teams, nil
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

// removeKey 删掉一个 Team 的上传 Key 目录（<keys>/<TEAMID>/，按租户时 <keys>/tenants/<租户>/<TEAMID>/）。
//
// 只删这一格，而且不跟符号链接：租户与 Team ID 已经按形状校验过，拼出来的路径就在 keys 下面；
// 那一格如果是个链接，删的是链接本身，不会顺着它删到别处去。本来就没有算成功——要的结果
// 是"这台机器上没有这把 Key"，已经是了。
func removeKey(stdout io.Writer, keysDir, tenant, team string) error {
	dir := keyDir(keysDir, tenant, team)
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return json.NewEncoder(stdout).Encode(map[string]any{"removed": true, "existed": false})
	case err != nil:
		return fmt.Errorf("cannot inspect the upload key of %s: %w", team, err)
	case info.Mode()&os.ModeSymlink != 0:
		if err := os.Remove(dir); err != nil {
			return fmt.Errorf("cannot remove %s: %w", dir, err)
		}
	default:
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("cannot remove %s: %w", dir, err)
		}
	}
	return json.NewEncoder(stdout).Encode(map[string]any{"removed": true, "existed": true})
}
