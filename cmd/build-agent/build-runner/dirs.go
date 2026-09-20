package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/Helix2010/RN-Server/cmd/build-agent/internal/jobspec"
)

// statOwner 用 Lstat：路径最后一段是符号链接时一律按"不是我们要的东西"处理。
func statOwner(path string) (fs.FileInfo, int, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, 0, fmt.Errorf("%s: cannot read the owner", path)
	}
	return info, int(st.Uid), nil
}

// expectControllerDir 校验一个应当由控制进程准备、执行进程不能改写的目录。
func expectControllerDir(who identity, path, what string, allowGroupWrite bool) error {
	info, owner, err := statOwner(path)
	if err != nil {
		return fmt.Errorf("%s is not there: %w", what, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s must be a real directory", what)
	}
	if !who.separated {
		return nil
	}
	if owner != who.sudoUID {
		return fmt.Errorf("%s must belong to the controller (uid %d), not uid %d", what, who.sudoUID, owner)
	}
	perm := info.Mode().Perm()
	if perm&0o002 != 0 {
		return fmt.Errorf("%s must not be world-writable", what)
	}
	if !allowGroupWrite && perm&0o020 != 0 {
		return fmt.Errorf("%s must not be writable by the build user", what)
	}
	return nil
}

func checkRoot(who identity, root string) error {
	if err := jobspec.ValidRoot(root); err != nil {
		return err
	}
	return expectControllerDir(who, root, "the jobs root", false)
}

// checkJobDir 校验任务目录。build 还要求 spec.json 与 src/ 在位；cleanup 只要求目录本身。
func checkJobDir(who identity, root, jobID string, forBuild bool) (jobspec.Layout, error) {
	layout, err := jobspec.NewLayout(root, jobID)
	if err != nil {
		return layout, err
	}
	if err := checkRoot(who, root); err != nil {
		return layout, err
	}
	if err := expectControllerDir(who, layout.Dir(), "the job directory", false); err != nil {
		return layout, err
	}
	// work/ 与 out/ 是控制进程建好、交给执行进程写的（setgid 组可写）
	if err := expectControllerDir(who, layout.Work(), "work/", true); err != nil {
		return layout, err
	}
	if err := expectControllerDir(who, layout.Out(), "out/", true); err != nil {
		return layout, err
	}
	if !forBuild {
		return layout, nil
	}
	if err := expectControllerDir(who, layout.Src(), "src/", false); err != nil {
		return layout, err
	}
	info, owner, err := statOwner(layout.Spec())
	if err != nil {
		return layout, fmt.Errorf("spec.json is not there: %w", err)
	}
	if !info.Mode().IsRegular() {
		return layout, errors.New("spec.json must be a regular file")
	}
	if who.separated && (owner != who.sudoUID || info.Mode().Perm()&0o022 != 0) {
		return layout, errors.New("spec.json must belong to the controller and not be writable by anyone else")
	}
	return layout, nil
}

// readSpec 读任务说明：不跟随符号链接、有大小上限、严格解析、按布局校验。
func readSpec(layout jobspec.Layout, kind jobspec.Kind) (jobspec.Spec, error) {
	file, err := os.OpenFile(layout.Spec(), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return jobspec.Spec{}, err
	}
	defer file.Close()
	spec, err := jobspec.DecodeSpec(file)
	if err != nil {
		return spec, err
	}
	if err := spec.Validate(layout); err != nil {
		return spec, err
	}
	if spec.Kind != kind {
		return spec, fmt.Errorf("the job is %s but --kind says %s", spec.Kind, kind)
	}
	return spec, nil
}

// reap 在分离模式下清掉 builder 用户留下的一切进程与临时文件，让攻击者在执行进程里能做的事
// 以一个任务为界：Gradle daemon、自己 setsid 出去的后台进程、/tmp 里的 Metro 缓存都活不过
// 下一个任务的开始。
//
// **不用 `kill(-1)`**。它的文档说"发给本 uid 的全部进程，排除调用者自己"，Linux 上确实如此，
// macOS 上**不成立**——2026-09-20 真机上一行就验出来了：
//
//	sudo -u _rnbuilder /bin/sh -c '/bin/kill -9 -1; echo survived'   → zsh: killed
//
// 表现是 `build` 与 `cleanup` 一进来就被 SIGKILL：零输出、退出码 -1。而不调 reap 的
// self-check / ios-inventory / install-ios-material 全都正常——差别只有这一条。排查里
// 排除过代码签名、sudoers、`--`、空环境与两层 sudo。
//
// 改成**点名杀**：自己列出本 uid 的进程，跳过自己与自己的整条祖先链（sudo 是 root 的，本来
// 也杀不动），剩下的一个个发 SIGKILL。副作用是多起一个 ps 子进程，换来的是这一步不会再把
// 调用者自己带走——而它恰恰是"每个任务都从干净状态开始"这条性质的唯一执行者。
func reap(who identity) {
	if !who.separated {
		return
	}
	for _, pid := range strayPIDs(who.uid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	for _, dir := range reapDirs(runtime.GOOS, who.uid, darwinVarFolders) {
		sweepOwned(dir, who.uid)
	}
}

// psCommand 列出进程表。绝对路径，不走 PATH——这个程序里跑着第三方依赖的代码。
// 做成变量只为测试。
var psCommand = func() *exec.Cmd {
	// macOS 在 /bin/ps，Debian 两处都有；都不在就取不到进程表，reap 什么都不杀
	path := "/bin/ps"
	if _, err := os.Stat(path); err != nil {
		path = "/usr/bin/ps"
	}
	return exec.Command(path, "-Ao", "pid=,ppid=,uid=")
}

// strayPIDs 是这个 uid 名下、除了自己与自己祖先之外的进程。
//
// 祖先也要跳过：经 sudo 时父进程是 root，杀不动也无所谓；不经 sudo 的本地形态下 reap 根本
// 不跑。但把整条链排除掉，这个函数的性质就与"谁调它"无关——不必依赖某一种启动方式。
func strayPIDs(uid int) []int {
	out, err := psCommand().Output()
	if err != nil {
		return nil
	}
	type entry struct{ ppid, uid int }
	table := map[int]entry{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		pid, err1 := strconv.Atoi(fields[0])
		ppid, err2 := strconv.Atoi(fields[1])
		owner, err3 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		table[pid] = entry{ppid: ppid, uid: owner}
	}
	// 自己与自己的祖先：从本进程往上走，链上每一个都留着
	keep := map[int]bool{}
	for pid := os.Getpid(); pid > 1; {
		if keep[pid] {
			break // 进程表读到一半变了，出现了环；停下比绕死强
		}
		keep[pid] = true
		parent, ok := table[pid]
		if !ok {
			break
		}
		pid = parent.ppid
	}
	var stray []int
	for pid, e := range table {
		if e.uid == uid && !keep[pid] && pid > 1 {
			stray = append(stray, pid)
		}
	}
	sort.Ints(stray)
	return stray
}

// darwinVarFolders 是 macOS 每用户临时目录的根。
const darwinVarFolders = "/var/folders"

// reapDirs 是这台机器上要清的临时目录。
//
// Linux 与 macOS 的差别不是"多一个少一个"，而是**macOS 上真正会积累东西的那两个目录不在
// 这张清单的默认位置上**：Xcode、CocoaPods 与 Metro 写的是每用户的
// `/var/folders/<xx>/<yyyy>/{T,C}`（`confstr(_CS_DARWIN_USER_TEMP_DIR)` 与 `…CACHE_DIR`），
// 它们**不吃 `TMPDIR`**——把 TMPDIR 指到任务目录也拦不住。不扫这两个目录，一是磁盘会长期
// 涨（DerivedData 之外还有几个 G 的中间产物），二是"执行进程里能做的事以一个任务为界"这条
// 就不成立了：上一个任务留下的东西下一个任务还读得到。
//
// `/dev/shm` 反过来只有 Linux 有；macOS 上它不存在，扫它只是白跑一次 ReadDir。
func reapDirs(goos string, uid int, varFolders string) []string {
	dirs := []string{"/tmp", "/var/tmp"}
	if goos == "darwin" {
		return append(dirs, darwinPerUserTempDirs(varFolders, uid)...)
	}
	return append(dirs, "/dev/shm")
}

// darwinPerUserTempDirs 找出属于 uid 的每用户临时与缓存目录。
//
// 不调 `getconf DARWIN_USER_TEMP_DIR`，也不调 `confstr`：那两个回的是**当前进程**的目录，
// 而每用户目录是按 uid 与 bootstrap 命名空间分的——执行进程在不同的 launchd 会话里跑过，
// 就会留下不止一个。直接按属主扫 `/var/folders` 能把它们都找出来，而且不用起子进程。
//
// `/var/folders/<xx>` 是 root 的、可读；下一层 `<yyyy>` 才是用户的 0700。只按第二层的属主
// 判断，别人的目录连名字都不动。
func darwinPerUserTempDirs(varFolders string, uid int) []string {
	var dirs []string
	outer, err := os.ReadDir(varFolders)
	if err != nil {
		return nil
	}
	for _, first := range outer {
		if !first.IsDir() {
			continue
		}
		inner, err := os.ReadDir(filepath.Join(varFolders, first.Name()))
		if err != nil {
			continue
		}
		for _, second := range inner {
			path := filepath.Join(varFolders, first.Name(), second.Name())
			info, owner, err := statOwner(path)
			if err != nil || owner != uid || !info.IsDir() {
				continue
			}
			// T 与 C 本身留着（系统按这两个名字找它们），只清里面
			dirs = append(dirs, filepath.Join(path, "T"), filepath.Join(path, "C"))
		}
	}
	return dirs
}

// sweepOwned 删掉 dir 顶层里属于 uid 的条目（整棵删）。别人的东西不动。
func sweepOwned(dir string, uid int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		_, owner, err := statOwner(path)
		if err != nil || owner != uid {
			continue
		}
		_ = removeAllOwned(path)
	}
}

// removeAllOwned 删除一棵目录树。执行进程里的代码可以把自己的目录改成 000 来阻止删除，
// 所以先把能改的目录权限改回 0700 再删；不跟随符号链接。
func removeAllOwned(path string) error {
	// WalkDir 先对目录调回调、再读目录内容，所以在回调里改权限就能走进 000 的目录
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o700)
		}
		return nil
	})
	return os.RemoveAll(path)
}

// emptyDir 删掉目录里的全部条目，目录本身（属控制进程）留着。
func emptyDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var first error
	for _, entry := range entries {
		if err := removeAllOwned(filepath.Join(dir, entry.Name())); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func ensureEmpty(dir, what string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("%s is not empty; a job directory is used once", what)
	}
	return nil
}

// copyTree 把控制进程的检出复制成执行进程自己的一份：普通文件、目录、符号链接照原样
// （链接不跟随），其它类型拒收。副本全部属于执行进程，pnpm、Gradle、expo prebuild
// 改权限、删目录都不会撞上别人的文件。
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		switch mode := info.Mode(); {
		case mode.IsDir():
			return os.Mkdir(target, 0o750)
		case mode&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		case mode.IsRegular():
			perm := fs.FileMode(0o640)
			if mode.Perm()&0o100 != 0 {
				perm = 0o750
			}
			return copyFile(path, target, perm)
		default:
			return fmt.Errorf("refusing to copy %s: not a regular file, directory or symlink", rel)
		}
	})
}

// copyFile 以独占方式创建目标并复制内容，源文件不跟随符号链接。
func copyFile(src, dst string, perm fs.FileMode) error {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", filepath.Base(src))
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
