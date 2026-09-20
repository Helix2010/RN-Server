package main

// ios-inventory：把签名区里**控制进程读不到**的东西取出来交给它。
//
// 签名区归这个账户（_rnbuilder 0700），控制进程（_rnbuildagent）连目录都 stat 不了，
// 而它又要盘点"这台机器能签哪些 Team"（设计 §5.4）。中间这一段由这里补上：两条 security
// 的标准输出、profiles/ 下每份描述文件的原文，一并按 JSON 打到标准输出。
//
// 只给原文，不给结论——解析、判过期、判"少了什么"全在控制进程那一侧。跑第三方构建代码
// 的是这个账户，"这台机器报上去的能力"不该由它说了算。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
)

// iosInventory 读签名区，把 JSON 写到 out。
func iosInventory(ctx context.Context, out io.Writer, who identity, dir string) error {
	if err := checkSigningDir(who, dir); err != nil {
		return usageError{err}
	}
	material := jobspec.IOSMaterial{Profiles: map[string][]byte{}}
	keychain := filepath.Join(dir, jobspec.IOSKeychainFileName)
	// 两条命令必须在**同一个进程**里。`find-identity -v` 的 `-v` 要做一次信任评估，而评估
	// 时中间证书（Apple 的 WWDR）是按**钥匙串搜索列表**找的——它就躺在这个独立钥匙串里，
	// 可这个钥匙串不在搜索列表上，于是链建不起来，`find-identity` 报 0 个有效身份**且不报错**。
	//
	// 2026-09-20 真机上就是这样：叶子证书、WWDR、Apple Root CA 三张都在钥匙串里，
	// `security verify-cert -p codeSign` 说链没问题，盘点却一个 Team 都不报，日志上只有
	// 一句"钥匙串里没有 Apple Distribution 身份"。签名那条路一直是对的（iossigning.go
	// 把 list-keychains 放在同一个 `security -i` 里），盘点这条路从来没跟上。
	//
	// 只改这一个进程的搜索列表：`list-keychains -s` 要把设置写进 $HOME，而这个账户的家目录
	// 是 /var/empty，写不进去——正好，只读的盘点本来也不该在账户上留下状态。解锁不需要，
	// 真机上验过：光加这一条就够了。
	if text, err := securityScript(ctx,
		"list-keychains -s "+keychain,
		"find-identity -v -p codesigning "+keychain,
	); err != nil {
		material.IdentitiesError = oneLine(err.Error())
	} else {
		material.Identities = text
	}
	if text, err := securityOutput(ctx, "find-certificate", "-a", "-p", keychain); err != nil {
		material.CertificatesError = oneLine(err.Error())
	} else {
		material.Certificates = text
	}
	material.Problems = readProfiles(filepath.Join(dir, jobspec.IOSProfilesDirName), material.Profiles)
	return json.NewEncoder(out).Encode(material)
}

// checkSigningDir 只收这个账户自己的目录。控制进程是唯一的调用方，它比这里更可信，
// 所以这不是防它——是防"参数写错了就去读别人的目录"，以及让错误当场说清楚。
func checkSigningDir(who identity, dir string) error {
	// 字母表照 iosSigningPathPattern：这个路径会被拼进 `security -i` 的一行命令，
	// 而那里按空白切词，带空格的路径会被切成别的参数
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || !iosSigningPathPattern.MatchString(dir) {
		return fmt.Errorf("--signing-dir must be an absolute, clean path of letters, digits and ._-/ (got %q)", dir)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("--signing-dir: %w", err)
	}
	switch {
	case info.Mode()&fs.ModeSymlink != 0 || !info.IsDir():
		return fmt.Errorf("%s is not a real directory", dir)
	case info.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s is writable by group or others", dir)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != who.uid {
		return fmt.Errorf("%s does not belong to the build user (uid %d): the signing material lives in the build user's own directory", dir, who.uid)
	}
	return nil
}

// readProfiles 读 profiles/<TEAMID>/*.mobileprovision 的原文，回"看见了但读不了"的那些。
func readProfiles(root string, into map[string][]byte) []string {
	var problems []string
	teams, err := os.ReadDir(root)
	if err != nil {
		if !os.IsNotExist(err) {
			problems = append(problems, "cannot read "+root+": "+err.Error())
		}
		return problems
	}
	sort.Slice(teams, func(i, j int) bool { return teams[i].Name() < teams[j].Name() })
	count := 0
	for _, team := range teams {
		if !team.IsDir() {
			continue
		}
		dir := filepath.Join(root, team.Name())
		files, err := os.ReadDir(dir)
		if err != nil {
			problems = append(problems, "cannot read "+dir+": "+err.Error())
			continue
		}
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), jobspec.IOSProfileSuffix) {
				continue
			}
			if count >= jobspec.IOSProfileMaxCount {
				problems = append(problems, root+" holds more than "+fmt.Sprint(jobspec.IOSProfileMaxCount)+" profiles; the rest were not read")
				return problems
			}
			path := filepath.Join(dir, file.Name())
			raw, err := readCapped(path)
			if err != nil {
				problems = append(problems, "cannot read "+path+": "+err.Error())
				continue
			}
			into[team.Name()+"/"+file.Name()] = raw
			count++
		}
	}
	return problems
}

// readCapped 读一个普通文件，超过上限就报错而不是读进来。
func readCapped(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	switch {
	case err != nil:
		return nil, err
	case !info.Mode().IsRegular():
		return nil, fmt.Errorf("not a regular file")
	case info.Size() > jobspec.IOSProfileMaxBytes:
		return nil, fmt.Errorf("%d bytes is larger than the %d byte limit for a provisioning profile", info.Size(), jobspec.IOSProfileMaxBytes)
	}
	return io.ReadAll(io.LimitReader(file, jobspec.IOSProfileMaxBytes))
}

// securityScript 把几条 security 子命令经标准输入喂给同一个 `security -i` 进程，收标准输出。
//
// 需要"前一条命令的效果对后一条可见"时用它——比如设搜索列表再问身份（见 iosInventory）。
func securityScript(ctx context.Context, lines ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := securityInteractive(ctx)
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if len(detail) > 200 {
			detail = detail[:200]
		}
		return "", fmt.Errorf("security -i (%s): %w: %s", strings.Join(lines, "; "), err, detail)
	}
	return stdout.String(), nil
}

// securityInteractive 起 `security -i`。测试换掉它——macOS 才有这个程序。
var securityInteractive = func(ctx context.Context) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "/usr/bin/security", "-i")
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	return cmd
}

// securityOutput 跑一条 `security` 子命令并收标准输出。超时是为了不让一次卡住的钥匙串
// 把控制进程的认领循环停住：认领每 10 秒一次。
func securityOutput(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/security", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if len(detail) > 200 {
			detail = detail[:200]
		}
		return "", fmt.Errorf("security %s: %w: %s", strings.Join(args, " "), err, detail)
	}
	return stdout.String(), nil
}
