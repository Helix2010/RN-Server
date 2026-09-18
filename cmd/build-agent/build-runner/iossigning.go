package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
)

// iOS 构建前的签名准备（设计 ios-mac-builders-home-network-2026-09-18 §4.2、§4.3b）。
//
// 问题：子进程的 HOME 是**这次任务自己的目录**（jobspec.jobPathEnv，为的是 pnpm 与
// DerivedData 的隔离），而 macOS 把钥匙串搜索列表存在 ~/Library/Preferences/、登录钥匙串
// 存在 ~/Library/Keychains/——HOME 一换，codesign 什么证书都找不到。
//
// 做法：钥匙串放固定路径（不在任务目录里，用完不删），每个任务开始时在任务 HOME 里把它
// 设成搜索列表、解锁、关掉自动上锁，并把描述文件复制进任务 HOME 的两个目录（Xcode 16 起
// 读 UserData 那个，旧版读 MobileDevice 那个，两处都放）。钥匙串路径还会显式传给
// xcodebuild（OTHER_CODE_SIGN_FLAGS=--keychain），不赌搜索列表能被 $HOME 带过去。

const (
	iosKeychainName         = "rn-signing.keychain-db"
	iosKeychainPasswordName = "rn-signing.password"
	iosProfilesDirName      = "profiles"
	iosProfileSuffix        = ".mobileprovision"
)

// 描述文件在任务 HOME 里的两个去处。Xcode 16 起读第一个，更早的版本读第二个。
var iosProfileHomeDirs = []string{
	"Library/Developer/Xcode/UserData/Provisioning Profiles",
	"Library/MobileDevice/Provisioning Profiles",
}

var (
	// iosSigningPathPattern：签名目录会被拼进 `security` 的交互式命令行，只许不需要引号的字符。
	// 它来自机器级环境变量（装机脚本写的），不是任务参数，但执行进程对任何输入都按不可信处理
	iosSigningPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	// 钥匙串口令由装机脚本随机生成，字母数字加 _-。限定字母表是为了让它能安全地出现在
	// `security -i` 的一行命令里
	iosKeychainPasswordPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

// prepareIOSSigning 让这次任务的 HOME 能签名，返回签名材料目录。
func (j job) prepareIOSSigning(ctx context.Context) (string, error) {
	dir := jobspec.EnvValue(j.spec.Env, jobspec.IOSSigningDirEnv)
	if dir == "" {
		return "", fmt.Errorf("%s is not set: an iOS build machine needs the directory that holds the keychain and the provisioning profiles", jobspec.IOSSigningDirEnv)
	}
	if !iosSigningPathPattern.MatchString(dir) || filepath.Clean(dir) != dir {
		return "", fmt.Errorf("%s must be a clean absolute path of letters, digits and ._-/ (got %q)", jobspec.IOSSigningDirEnv, dir)
	}
	keychain := filepath.Join(dir, iosKeychainName)
	if info, err := os.Lstat(keychain); err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file: import this machine's signing certificates into it first", keychain)
	}
	password, err := readKeychainPassword(filepath.Join(dir, iosKeychainPasswordName))
	if err != nil {
		return "", err
	}
	// 三条命令走 `security -i` 的标准输入，而不是三次命令行调用：口令要是出现在
	// 命令行参数里，这台机器上任何一个用户 `ps` 一下就看得到（AGENTS.md「机密的操作纪律」）。
	//
	//   list-keychains -d user -s <钥匙串>   把它写进**任务 HOME** 的搜索列表
	//   unlock-keychain -p <口令> <钥匙串>   解锁
	//   set-keychain-settings <钥匙串>       不自动上锁（一次构建可能跑一小时）
	script := strings.Join([]string{
		"list-keychains -d user -s " + keychain,
		"unlock-keychain -p " + password + " " + keychain,
		"set-keychain-settings " + keychain,
		"",
	}, "\n")
	cmd, err := j.command(ctx, "security", "-i")
	if err != nil {
		return "", fmt.Errorf("cannot run security: %w", err)
	}
	var out bytes.Buffer
	cmd.Stdin = strings.NewReader(script)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		// security 不回显口令，但失败路径上的输出是最容易漏掉的一条泄漏路径，
		// 所以无论如何先把它从输出里抹掉再打
		return "", fmt.Errorf("cannot make the signing keychain usable in this job's HOME: %w: %s",
			err, strings.ReplaceAll(strings.TrimSpace(out.String()), password, "<keychain password>"))
	}
	copied, err := j.copyProvisioningProfiles(dir)
	if err != nil {
		return "", err
	}
	logf(j.out, "signing keychain unlocked; %d provisioning profiles copied into this job's HOME", copied)
	return dir, nil
}

// readKeychainPassword 读钥匙串口令并校验字母表。
//
// 这个文件对执行进程可读——也就是对第三方构建代码可读。设计 §10 第 4 条承认了这一点：
// 替代方案是每次任务由人解锁，与无人值守冲突。这里能做的只是不让它再多泄一处。
func readKeychainPassword(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read the keychain password file: %w", err)
	}
	password := strings.TrimRight(string(raw), "\r\n")
	if !iosKeychainPasswordPattern.MatchString(password) {
		return "", errors.New("the keychain password file must hold 16-128 characters of letters, digits, _ and - " +
			"(the machine installer generates it; a password with other characters cannot be passed to security safely)")
	}
	return password, nil
}

// copyProvisioningProfiles 把签名目录下**所有** Team 的描述文件复制进任务 HOME 的两个目录。
//
// 全部复制而不是只挑这个租户的：描述文件不是机密（§4.4），而挑选需要执行进程知道
// "这次要签哪个 bundle id"，那等于把一次判断搬到不可信的一侧。Xcode 按
// PROVISIONING_PROFILE_SPECIFIER 的名字选，多放几份不会选错。
func (j job) copyProvisioningProfiles(signingDir string) (int, error) {
	root := filepath.Join(signingDir, iosProfilesDirName)
	targets := make([]string, 0, len(iosProfileHomeDirs))
	for _, rel := range iosProfileHomeDirs {
		target := filepath.Join(j.layout.Home(), rel)
		if err := os.MkdirAll(target, 0o700); err != nil {
			return 0, err
		}
		targets = append(targets, target)
	}
	teams, err := os.ReadDir(root)
	if err != nil {
		return 0, fmt.Errorf("cannot read the provisioning profiles in %s: %w", root, err)
	}
	copied := 0
	for _, team := range teams {
		if !team.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(root, team.Name()))
		if err != nil {
			return 0, err
		}
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), iosProfileSuffix) {
				continue
			}
			source := filepath.Join(root, team.Name(), file.Name())
			for _, target := range targets {
				// 文件名带上 Team：两个 Team 各有一份 wallet.mobileprovision 时不会互相覆盖
				if err := copyFile(source, filepath.Join(target, team.Name()+"-"+file.Name()), 0o600); err != nil {
					return 0, fmt.Errorf("cannot copy %s into this job's HOME: %w", source, err)
				}
			}
			copied++
		}
	}
	if copied == 0 {
		return 0, fmt.Errorf("no provisioning profiles under %s: this machine cannot sign anything", root)
	}
	return copied, nil
}

// xcodeToolchain 是这台机器的 Xcode 版本，形如 `Xcode 16.2 (16C5032a)`。
//
// 直接问 xcodebuild，而不是从构建脚本的输出里捞一行：那样这个值的正确性就取决于另一个
// 仓库里某行日志的格式。读不出来不让任务失败——它只是一个用来发现版本漂移的记录。
func (j job) xcodeToolchain(ctx context.Context) string {
	cmd, err := j.command(ctx, "xcodebuild", "-version")
	if err != nil {
		return ""
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		logf(j.out, "cannot read the Xcode version: %v", err)
		return ""
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	version := strings.TrimSpace(lines[0])
	if len(lines) > 1 {
		build := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[1]), "Build version"))
		if build != "" {
			version += " (" + build + ")"
		}
	}
	if len(version) > jobspec.MaxToolchainLength {
		version = version[:jobspec.MaxToolchainLength]
	}
	return version
}
