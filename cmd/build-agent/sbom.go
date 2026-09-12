package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SBOM 在**打包机上**生成，跟着那次构建自己的依赖树走。
//
// 它原来挂在 RN-App 的 CI 里（app-quality.yml 的 android-release-gate）。那条门禁
// 随 CI 一起撤掉之后，SBOM 就落在了没有人跑的地方——而这正是它最不该在的状态：
// 一份"上次发版时生成过"的物料清单，和没有是一样的。
//
// 放这里还有一个 CI 给不了的性质：扫的是**真正产出那个 APK 的那棵依赖树**，同一个
// worktree、同一次 pnpm install。CI 里扫的是另一台机器上另一次安装的结果，两边理论
// 上应该一致，但"应该一致"不是证据。
//
// 失败就让整个任务失败，不降级成警告。SBOM 是安全评审 §12.2 要求的发布门禁，而
// 一个静默跳过的门禁比没有门禁更坏——它让人以为已经查过了。build-sbom.mjs 自己也
// 是按这条原则写的（见其中的 MIN_COMPONENTS）。
const sbomFileSuffix = "-sbom.cdx.json"

// generateSBOM 调仓库里的 scripts/build-sbom.mjs，产出一份绑定到这个 APK 的
// CycloneDX 文档，返回它的路径。
//
// 绑定的意思是文档里写着这个包的 sha256、包名、版本、build 号和 commit——不绑定的
// SBOM 只是"某次扫描的结果"，回答不了"用户手机上那个包里装的是哪个版本"。
func generateSBOM(ctx context.Context, buf *logBuffer, worktree, tenantDirectory, apkPath string, env []string) (string, error) {
	script := filepath.Join(worktree, "scripts", "build-sbom.mjs")
	if _, err := os.Stat(script); err != nil {
		return "", fmt.Errorf("this checkout has no scripts/build-sbom.mjs, so no SBOM can be produced: %w", err)
	}
	out := strings.TrimSuffix(apkPath, filepath.Ext(apkPath)) + sbomFileSuffix
	if err := run(ctx, buf, worktree, env, "node", script,
		"--root", worktree, "--tenant", tenantDirectory, "--apk", apkPath, "--out", out); err != nil {
		// syft 不在 PATH 上是这里最常见的失败，而脚本已经把安装地址打进日志了；
		// 这里只补一句"装在哪台机器上"——看日志的人未必知道这一步跑在打包机上。
		return "", fmt.Errorf("SBOM generation failed on the build machine (is syft installed? deploy/amos/install-syft.sh): %w", err)
	}
	if _, err := os.Stat(out); err != nil {
		return "", fmt.Errorf("build-sbom.mjs reported success but %s is not there: %w", filepath.Base(out), err)
	}
	return out, nil
}
