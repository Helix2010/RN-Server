package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Helix2010/RN-Server/internal/androidkeystore"
)

// 租户身份文件由服务端合成、随任务下发，代理把它写进本次任务的 worktree。
//
// 这里原来是 applyBuildVersion + assertOnlyVersionChanged：文件在仓库里，代理只
// 允许任务改 version 和 androidVersionCode，动到第三个字段就判失败。那道闸的依据
// 是"仓库里那一份是权威"。2026-09-12 文件搬到了服务端，依据没了，闸也就无从比起。
//
// 换进来的是 validateTenantFile。它挡不住"服务端下发了一个不同的包名"——那件事现在
// 由控制台的 acknowledgeIdentityChange 和 queueBuild 的漂移检查负责。它挡的是另一
// 类：字段缺失、格式不对、或者拿 React Native 那把**公开的 debug 签名指纹**去当自
// 校验基准。这类错误如果放过去，产出的是一个能装、但装上去才发现起不来的包。
//
// 两端各校验一次是故意的：服务端和代理分属不同的信任域，路径拼接和身份字段这两类
// 输入，各自把住自己那一侧。
var (
	packagePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)
	sha256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	addressPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
)

// React Native 模板自带的 debug keystore 的证书指纹。它的私钥在每一台装了 RN 的
// 机器上，谁都能用它签一个同包名的 APK 原地覆盖安装。拿它当 signerSha256 等于
// 把自校验关掉，还留下一行"已经校验过了"的假象。
//
// 2026-09-12 修正：原先这里写的是 a40da80a59d170caa950cf15c18c454d47a39b26 后面
// 补了 12 个字节——那前 20 个字节是 debug key 的 **SHA-1**。指纹是 SHA-256，两者
// 永远不会相等，所以这道闸从来没有生效过：一条恒假的断言比没有断言更坏，因为它
// 让人以为这里已经拦住了。值与服务端共用一处定义，见 androidkeystore。
const reactNativeDebugSigner = androidkeystore.PublicDebugSignerSHA256

func writeTenantFile(worktree, directory string, raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("the job carries no tenant file; the server could not compose this tenant's app identity")
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return "", fmt.Errorf("tenant file is not JSON: %w", err)
	}
	if err := validateTenantFile(manifest); err != nil {
		return "", err
	}
	dir := filepath.Join(worktree, "tenants", directory)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create tenant directory: %w", err)
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "tenant.json")
	if err := os.WriteFile(path, append(encoded, '\n'), 0o640); err != nil {
		return "", fmt.Errorf("write tenant file: %w", err)
	}
	return path, nil
}

func validateTenantFile(manifest map[string]any) error {
	text := func(key string) string {
		v, _ := manifest[key].(string)
		return strings.TrimSpace(v)
	}
	for _, key := range []string{"slug", "appName", "androidPackage", "apiBaseUrl", "bootstrapSignerAddress", "signerSha256", "version"} {
		if text(key) == "" {
			return fmt.Errorf("tenant file is missing %q", key)
		}
	}
	if !packagePattern.MatchString(text("androidPackage")) {
		return fmt.Errorf("androidPackage %q is not a reverse-DNS application id", text("androidPackage"))
	}
	if !strings.HasPrefix(text("apiBaseUrl"), "https://") {
		// 客户端对配置的信任来自签名，而签名挡不住"根本没连到我们"
		return fmt.Errorf("apiBaseUrl %q must be https", text("apiBaseUrl"))
	}
	if !addressPattern.MatchString(text("bootstrapSignerAddress")) {
		return fmt.Errorf("bootstrapSignerAddress %q is not an address", text("bootstrapSignerAddress"))
	}
	signer := strings.ToLower(text("signerSha256"))
	if !sha256Pattern.MatchString(signer) {
		return fmt.Errorf("signerSha256 must be 64 lowercase hex characters")
	}
	if signer == reactNativeDebugSigner {
		return fmt.Errorf("signerSha256 is the public React Native debug key; that disables the app's own signer check")
	}
	if code, ok := manifest["androidVersionCode"].(float64); !ok || code < 1 {
		return fmt.Errorf("androidVersionCode must be a positive integer")
	}
	return nil
}
