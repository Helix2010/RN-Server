// rn-build-agent-upgrade 是 Mac 打包机上的升级程序，以 root 运行，由 launchd 在停机标记
// 出现时触发（WatchPaths）。
//
//	rn-build-agent-upgrade [--env /var/rn-build-agent/env] [--install-dir /opt/rn-build-agent]
//
// 它做的事（设计 docs/design/ios-mac-builders-home-network-2026-09-18.md §5.6）：
//
//	读停机标记 → 只认 `upgrade:<提交>` → 取清单、离线签名与归档 → **验签**、核单调序号、
//	核提交等于标记里那个 → 下载并逐个核对 sha256 → 冒烟 → 原子替换 → 删标记
//
// 为什么这些闸一个都不能少：自升级是整个方案里唯一一条"服务端能往每台 Mac 上放可执行
// 代码"的路，而每台 Mac 上放着全部租户的签名材料。只校验 sha256 没有意义——那个 sha256
// 也是服务端给的。清单要由一把服务端手里没有的私钥签过（release-key.pub 在装机时按
// 密码管理器里的 sha256 核对过），序号要单调（防降级），提交要等于代理被告知的那一个
// （防服务端拿一份旧的、合法签过的清单顶替）。
//
// **无论成败都在退出前删掉停机标记**：不删的话 launchd 永远不会把代理拉起来，这台机器
// 就静悄悄地离线了；而失败时把原因写进 state/upgrade-failed.json，代理下次启动读出来
// 打进日志并随认领报给服务端。
package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Helix2010/RN-Server/signing/bundlesig"
)

const (
	defaultEnvFile    = "/var/rn-build-agent/env"
	defaultInstallDir = "/opt/rn-build-agent"
	haltFileName      = "halt"
	upgradePrefix     = "upgrade:"
	// sequenceFileName 记本机见过的最高签名序号。它放在 **root 拥有的安装目录**里，
	// 不放在代理的状态目录：状态目录属于代理那个用户，把防降级的水位线放在被防的一方
	// 能写的地方，这道闸就不成立了
	sequenceFileName = "upgrade-sequence"
	releaseKeyName   = "release-key.pub"
	// 二进制在归档里的位置，与 build-bundles.sh 一致
	binPrefix = "bin/"
	// downloadTimeout 是一次取件的**绝对上限**。真正起作用的是下面那个停滞看门狗：
	// 家用下行上一个 9 MB 的归档正常十几秒就完，而卡死的连接要么等对端重置（真机上
	// 实测 6–8 分钟），要么在这里干等半小时——两种都比"没新字节就重来"贵得多
	downloadTimeout = 30 * time.Minute
	// getAttempts：一次运行里就把重试用完。
	//
	// 不这样的话，重试要绕一整圈：升级失败 → 删停机标记 → launchd 拉起代理 → 认领 →
	// 409 → 再写标记 → 再触发这个程序 → **整包重下**。2026-09-20 真机上一次换版本因此
	// 花了 20 分钟，而升级本身只要 16 秒
	getAttempts     = 3
	maxArchiveBytes = 512 << 20
	maxFileBytes    = 256 << 20
)

// stallTimeout：连着这么久没有新字节（含等响应头）就判连接卡死，掐掉重来。
// getBackoff：两次重试之间等多久，按次数线性拉长。
//
// 做成变量只是为了测试能把它们调小——一次重试就等五秒的测试没人愿意跑。
var (
	stallTimeout = 60 * time.Second
	getBackoff   = 5 * time.Second
)

// 要换的可执行文件。多出来的文件（env 示例等）不动：这个程序只换代码。
//
// **自己排最后。**这个程序原先不换自己，于是它自己的 bug 只能靠人跑一遍装机脚本去修——
// 每台机器一次，而它恰恰是"没人能远程修"的那一个（2026-09-20 就撞上了：冒烟拿 root 的身份
// 去验控制进程的目录，所有 Mac 的自升级全卡住，修好也发不下去）。换自己是安全的：
// replaceBinary 走的是「写临时文件 + rename」，正在跑的这个进程仍然用着旧 inode，
// 下一次触发才是新的。排在最后是为了让前面那几个先换完——前面任何一步失败都不会动到它，
// 留在机器上的仍然是一个能跑的升级程序。
var upgradeBinaries = []string{"build-agent", "build-runner", "ios-upload", "rn-build-agent-upgrade"}

var (
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// 归档里允许出现的文件名：只有相对路径、没有 .. 与绝对路径
	safeNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	// 这个程序摆出来的东西要给**别的账户**用：换上去的 build-runner 由执行账户跑，换之前
	// 的自检也是。launchd 交给我们的 umask 不定，继承一个严一点的（027、077）会让解出来的
	// 二进制别人连执行都不行，而失败信息是一句没头没尾的 "Permission denied"。定死它。
	syscall.Umask(0o022)
	set := flag.NewFlagSet("rn-build-agent-upgrade", flag.ContinueOnError)
	set.SetOutput(stderr)
	envFile := set.String("env", defaultEnvFile, "the build agent env file (root owned)")
	installDir := set.String("install-dir", defaultInstallDir, "where the binaries live")
	baseURL := set.String("server", "", "override the server URL from the env file (tests only)")
	if err := set.Parse(args); err != nil || set.NArg() != 0 {
		return 2
	}
	env, err := readEnvFile(*envFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	stateDir := env["BUILD_AGENT_STATE_DIR"]
	if stateDir == "" {
		fmt.Fprintln(stderr, "BUILD_AGENT_STATE_DIR is not set in", *envFile)
		return 1
	}
	halt := filepath.Join(stateDir, haltFileName)
	target, ok := upgradeTarget(halt)
	if !ok {
		// 标记不在、或者不是"去升级"（例如机器被吊销）：这个程序什么都不做，
		// 尤其**不删**那个标记——吊销的机器就该停在那里
		fmt.Fprintln(stdout, "no upgrade was requested; nothing to do")
		return 0
	}
	server := strings.TrimRight(env["BUILD_AGENT_SERVER"], "/")
	if *baseURL != "" {
		server = strings.TrimRight(*baseURL, "/")
	}
	err = upgrade(context.Background(), upgradeInput{
		Server: server, Token: env["BUILD_AGENT_MACHINE_TOKEN"], InstallDir: *installDir,
		StateDir: stateDir, RunnerUser: env["BUILD_AGENT_RUNNER_USER"],
		Commit: target, Out: stdout,
	})
	// 成败都要删标记：不删的话 launchd 永远不会把代理拉起来，这台机器就静悄悄地离线了
	if removeErr := os.Remove(halt); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		fmt.Fprintln(stderr, "cannot remove the halt marker:", removeErr)
	}
	if err != nil {
		fmt.Fprintln(stderr, "upgrade failed:", err)
		if writeErr := writeFailure(stateDir, target, err); writeErr != nil {
			fmt.Fprintln(stderr, "cannot record the failure:", writeErr)
		}
		return 1
	}
	_ = os.Remove(filepath.Join(stateDir, "upgrade-failed.json"))
	fmt.Fprintln(stdout, "upgraded to", target)
	return 0
}

type upgradeInput struct {
	Server     string
	Token      string
	InstallDir string
	StateDir   string
	RunnerUser string
	Commit     string
	Out        io.Writer
}

func upgrade(ctx context.Context, in upgradeInput) error {
	switch {
	case in.Server == "" || in.Token == "":
		return errors.New("the env file has no server or machine token")
	case !commitPattern.MatchString(in.Commit):
		return fmt.Errorf("the halt marker names %q, which is not a commit", in.Commit)
	}
	public, err := readReleaseKey(filepath.Join(in.InstallDir, releaseKeyName))
	if err != nil {
		return err
	}
	described, err := describe(ctx, in)
	if err != nil {
		return err
	}
	// 1. 验签：清单必须由本机 pin 的那把发布密钥签过
	if err := bundlesig.Verify(public, described.Manifest, described.Signature); err != nil {
		return err
	}
	// 2. 单调序号：挡住"把机器降回一个当初确实被签过、但有已知漏洞的旧版"
	seen := readSequence(filepath.Join(in.InstallDir, sequenceFileName))
	if described.Signature.Sequence < seen {
		return fmt.Errorf("the signed manifest has sequence %d, below the %d this machine already accepted",
			described.Signature.Sequence, seen)
	}
	// 3. 提交：签名里的提交必须就是代理被告知要装的那一个。少了这一条，攻破服务端的人
	//    可以拿一份**合法签过的旧清单**配上改过的审批值顶替
	if described.Signature.Commit != in.Commit {
		return fmt.Errorf("the signed manifest is for commit %s, but this machine was told to install %s",
			described.Signature.Commit, in.Commit)
	}
	staging, err := os.MkdirTemp(in.InstallDir, ".upgrade-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	if err := download(ctx, in, described, staging); err != nil {
		return err
	}
	// 自检要以**执行账户**的身份跑 staging 里的 build-runner，而 MkdirTemp 建出来的目录
	// 是 0700 root：别的账户连进都进不去，sudo 只会回一句 "unable to execute …:
	// Permission denied"，看着像二进制坏了。等文件全部按签过的清单核对完再放开——放开的
	// 只是"能进来读"，目录仍归 root、别人写不了，而里面的字节与公开的安装包逐个对过。
	if err := os.Chmod(staging, 0o755); err != nil {
		return err
	}
	if err := smoke(ctx, in, staging); err != nil {
		return err
	}
	for _, name := range upgradeBinaries {
		source := filepath.Join(staging, binPrefix+name)
		if _, err := os.Stat(source); errors.Is(err, os.ErrNotExist) {
			// linux 那一组没有 ios-upload：不在归档里就不换，也不报错
			continue
		}
		if err := replaceBinary(source, filepath.Join(in.InstallDir, name)); err != nil {
			return fmt.Errorf("cannot install %s: %w", name, err)
		}
		fmt.Fprintln(in.Out, "installed", name)
	}
	return writeSequence(filepath.Join(in.InstallDir, sequenceFileName), described.Signature.Sequence)
}

// bundleDescription 是服务端那条描述接口的响应。
type bundleDescription struct {
	Manifest  []byte
	Signature bundlesig.Signature
	// Archive 的摘要与大小来自签过的清单，不是这条响应
	Archive archiveInfo
	Files   map[string]string
}

type archiveInfo struct {
	Name   string
	SHA256 string
	Size   int64
}

func describe(ctx context.Context, in upgradeInput) (bundleDescription, error) {
	var out bundleDescription
	query := "?os=" + runtime.GOOS + "&arch=" + runtime.GOARCH
	body, err := get(ctx, in, "/v1/build-agent/bundle"+query, 1<<20)
	if err != nil {
		return out, err
	}
	var payload struct {
		Bundle         string              `json:"bundle"`
		Commit         string              `json:"commit"`
		ManifestBase64 string              `json:"manifestBase64"`
		Signature      bundlesig.Signature `json:"signature"`
		Archive        struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
			Size   int64  `json:"size"`
			URL    string `json:"url"`
		} `json:"archive"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return out, fmt.Errorf("the server's bundle description is not JSON: %w", err)
	}
	manifest, err := base64.StdEncoding.DecodeString(payload.ManifestBase64)
	if err != nil {
		return out, fmt.Errorf("the manifest is not base64: %w", err)
	}
	archive, files, err := manifestBundle(manifest, payload.Bundle)
	if err != nil {
		return out, err
	}
	out.Manifest, out.Signature, out.Files = manifest, payload.Signature, files
	// **归档的摘要与大小取自清单，不取自这条响应**：响应是服务端现编的，它想改哪个字节
	// 就能把对应的摘要一起改掉。清单是签过的，那里的摘要它改不了
	out.Archive = archive
	return out, nil
}

// manifestBundle 从**签过的清单**里取归档的摘要、大小与每个文件的摘要。
//
// 这些值一个都不能从服务端那条描述响应里取：那条响应是服务端现编的，它想改哪个字节就能
// 把对应的摘要一起改掉。清单里的摘要被签名覆盖着，服务端改不了。
func manifestBundle(manifest []byte, bundle string) (archiveInfo, map[string]string, error) {
	var doc struct {
		Bundles map[string]struct {
			Archive       string `json:"archive"`
			ArchiveSHA256 string `json:"archiveSha256"`
			ArchiveSize   int64  `json:"archiveSize"`
			Files         []struct {
				Name   string `json:"name"`
				SHA256 string `json:"sha256"`
			} `json:"files"`
		} `json:"bundles"`
	}
	var archive archiveInfo
	if err := json.Unmarshal(manifest, &doc); err != nil {
		return archive, nil, fmt.Errorf("the signed manifest is not JSON: %w", err)
	}
	entry, ok := doc.Bundles[bundle]
	if !ok || len(entry.Files) == 0 {
		return archive, nil, fmt.Errorf("the signed manifest has no %s bundle", bundle)
	}
	if !digestPattern.MatchString(entry.ArchiveSHA256) || entry.ArchiveSize < 1 || entry.ArchiveSize > maxArchiveBytes {
		return archive, nil, errors.New("the signed manifest describes an archive this helper will not download")
	}
	archive = archiveInfo{Name: entry.Archive, SHA256: entry.ArchiveSHA256, Size: entry.ArchiveSize}
	files := map[string]string{}
	for _, file := range entry.Files {
		if !safeNamePattern.MatchString(file.Name) || strings.Contains(file.Name, "..") || !digestPattern.MatchString(file.SHA256) {
			return archive, nil, fmt.Errorf("the signed manifest lists a file this helper will not unpack: %q", file.Name)
		}
		files[file.Name] = file.SHA256
	}
	return archive, files, nil
}

// download 取归档、核对它的 sha256，解开并逐个核对每个文件的 sha256。
func download(ctx context.Context, in upgradeInput, described bundleDescription, staging string) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	query := "?os=" + runtime.GOOS + "&arch=" + runtime.GOARCH
	archive, err := get(ctx, in, "/v1/build-agent/bundle/archive"+query, described.Archive.Size+1)
	if err != nil {
		return err
	}
	if int64(len(archive)) != described.Archive.Size {
		return fmt.Errorf("the archive is %d bytes, the signed manifest says %d", len(archive), described.Archive.Size)
	}
	if sum := sha256.Sum256(archive); hex.EncodeToString(sum[:]) != described.Archive.SHA256 {
		return errors.New("the archive does not match the digest in the signed manifest")
	}
	return unpack(archive, staging, described.Files)
}

// unpack 解开归档。只解清单里列过的文件，其它一概跳过——清单是签过的，它就是这一组
// 安装包该有的样子；归档本身虽然摘要也对得上，但按清单解让"多塞一个文件"这件事不成立。
func unpack(archive []byte, staging string, files map[string]string) error {
	gz, err := gzip.NewReader(strings.NewReader(string(archive)))
	if err != nil {
		return fmt.Errorf("the archive is not gzip: %w", err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	seen := map[string]bool{}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("the archive is malformed: %w", err)
		}
		name := strings.TrimPrefix(filepath.Clean(header.Name), "./")
		want, listed := files[name]
		if !listed || header.Typeflag != tar.TypeReg {
			continue
		}
		if header.Size > maxFileBytes {
			return fmt.Errorf("%s in the archive is %d bytes", name, header.Size)
		}
		body, err := io.ReadAll(io.LimitReader(reader, maxFileBytes+1))
		if err != nil {
			return err
		}
		if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != want {
			return fmt.Errorf("%s in the archive does not match the signed manifest", name)
		}
		path := filepath.Join(staging, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if strings.HasPrefix(name, binPrefix) {
			mode = 0o755
		}
		if err := os.WriteFile(path, body, mode); err != nil {
			return err
		}
		seen[name] = true
	}
	for name := range files {
		if !seen[name] {
			return fmt.Errorf("%s is in the signed manifest but not in the archive", name)
		}
	}
	return nil
}

// sudoPath 只为测试可替换：真机上永远是 /usr/bin/sudo。
var sudoPath = "/usr/bin/sudo"

// smoke 在换上去之前先试一下新的二进制。
//
// 两条都很便宜，挡的却是最难查的一类故障：换上一个跑不起来的二进制之后，launchd 会把它
// 每秒拉起一次，而这台机器在控制台上只是"离线"。
func smoke(ctx context.Context, in upgradeInput, staging string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	// 空环境的 build-agent 必须以 2 退出（"配置不全"）：它证明这个二进制能在本机跑起来
	agent := exec.CommandContext(ctx, filepath.Join(staging, binPrefix+"build-agent"))
	agent.Env = []string{}
	if err := agent.Run(); exitCode(err) != 2 {
		return fmt.Errorf("the new build-agent exited with %d in an empty environment, expected 2", exitCode(err))
	}
	// build-runner 以执行进程的身份自检：它拒绝 root，也拒绝与启动它的用户同一个 uid
	if in.RunnerUser == "" || in.RunnerUser == "-" {
		return nil
	}
	// **不带 --jobs-root**：那条检查的判据是"任务根目录必须归调用者（SUDO_UID）"，而这里
	// 的调用者是 root，真机上任务根目录归控制账户——带上它，自检在任何一台真机上都必然失败
	// （2026-09-20 mac-01 撞上：uid 0 vs uid 201，升级反复停在这一步）。这一步要验的是
	// **新二进制**能不能以执行账户跑起来；"这台机器的目录摆对没有"由代理每次启动时自己查，
	// 那时调用者才真的是控制进程（cmd/build-agent/runnerexec.go checkRunner）。
	runner := exec.CommandContext(ctx, sudoPath, "-n", "-u", in.RunnerUser,
		filepath.Join(staging, binPrefix+"build-runner"), "self-check",
		"--protocol", "1", "--expect-separated")
	output, err := runner.CombinedOutput()
	if err != nil {
		return fmt.Errorf("the new build-runner failed its self-check as %s: %w: %s",
			in.RunnerUser, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return -1
}

// replaceBinary 原子替换：先写同目录下的临时文件，再 rename。
// 同目录是必要条件——跨文件系统的 rename 不是原子的。
func replaceBinary(source, target string) error {
	body, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	tmp := target + ".new"
	if err := os.WriteFile(tmp, body, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// upgradeTarget 读停机标记里的目标提交。只认 `upgrade:` 开头的。
func upgradeTarget(path string) (string, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	line := strings.TrimSpace(strings.SplitN(string(raw), "\n", 2)[0])
	if !strings.HasPrefix(line, upgradePrefix) {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(line, upgradePrefix)), true
}

func readSequence(path string) int64 {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || value < 0 {
		return 0
	}
	return value
}

func writeSequence(path string, sequence int64) error {
	return os.WriteFile(path, []byte(strconv.FormatInt(sequence, 10)+"\n"), 0o644)
}

func writeFailure(stateDir, commit string, cause error) error {
	raw, err := json.Marshal(map[string]string{
		"commit": commit, "error": cause.Error(), "at": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stateDir, "upgrade-failed.json"), append(raw, '\n'), 0o644)
}

// get 用机器令牌取一条，网络抖动时在**这一次运行里**重试。
//
// 只重试传输层的失败（连不上、连接被重置、读到一半卡死）。HTTP 状态码不重试：503
// 是"清单还没签"，4xx 是这台机器这一刻不该拿到这份包——重试它们只是把同一个答案
// 多问几遍，还把失败延后了十几秒。
func get(ctx context.Context, in upgradeInput, path string, limit int64) ([]byte, error) {
	var last error
	for attempt := 1; ; attempt++ {
		body, err := getOnce(ctx, in, path, limit)
		var transport transportError
		switch {
		case err == nil:
			return body, nil
		case !errors.As(err, &transport) || attempt >= getAttempts || ctx.Err() != nil:
			return nil, err
		}
		last = err
		fmt.Fprintf(in.Out, "%s failed (%v); retrying %d of %d\n", path, err, attempt+1, getAttempts)
		select {
		case <-ctx.Done():
			return nil, last
		case <-time.After(time.Duration(attempt) * getBackoff):
		}
	}
}

// transportError 是"网络没走通"，与"服务端明确答了别的"分开——只有前者值得重试。
type transportError struct{ err error }

func (e transportError) Error() string { return e.err.Error() }
func (e transportError) Unwrap() error { return e.err }

// getOnce 发一次请求。令牌只在请求头里，不进 URL、不进日志。
func getOnce(ctx context.Context, in upgradeInput, path string, limit int64) ([]byte, error) {
	// 停滞看门狗：每收到新字节就往后推一次；推不动了就取消这次请求。等响应头的那一段
	// 也算在内——真机上卡住的正是那一段
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stalled := false
	watchdog := time.AfterFunc(stallTimeout, func() { stalled = true; cancel() })
	defer watchdog.Stop()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, in.Server+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("x-machine-token", in.Token)
	client := &http.Client{
		Timeout: downloadTimeout,
		// 3xx 一律不跟：令牌在请求头里，跟一次跳转就可能把它发给别的主机
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, transportError{stallReason(err, stalled)}
	}
	defer response.Body.Close()
	watchdog.Reset(stallTimeout)
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4<<10))
		return nil, fmt.Errorf("%s returned %d: %s", path, response.StatusCode, strings.TrimSpace(string(body)))
	}
	reader := &stallReader{inner: response.Body, seen: func() { watchdog.Reset(stallTimeout) }}
	body, err := io.ReadAll(io.LimitReader(reader, limit))
	if err != nil {
		return nil, transportError{stallReason(err, stalled)}
	}
	return body, nil
}

// stallReason 把"看门狗掐的"说成人话——否则表现是一句没头没尾的 context canceled。
func stallReason(err error, stalled bool) error {
	if stalled {
		return fmt.Errorf("no new bytes for %s; the connection stalled", stallTimeout)
	}
	return fmt.Errorf("cannot reach the server: %w", err)
}

// stallReader 每读到字节就把看门狗往后推。
type stallReader struct {
	inner io.Reader
	seen  func()
}

func (r *stallReader) Read(p []byte) (int, error) {
	n, err := r.inner.Read(p)
	if n > 0 {
		r.seen()
	}
	return n, err
}

func readReleaseKey(path string) (public []byte, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the pinned release public key %s: %w", path, err)
	}
	key, err := bundlesig.ParsePublicKey(raw)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// readEnvFile 读 KEY=VALUE 形式的 env 文件（systemd / launchd 都用这个形状）。
// 值两侧的引号去掉；注释与空行跳过。
func readEnvFile(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		out[strings.TrimSpace(key)] = value
	}
	return out, nil
}
