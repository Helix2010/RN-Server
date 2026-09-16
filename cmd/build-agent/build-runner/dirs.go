package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
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
// kill(-1) 发给调用者有权发信号的全部进程（本 uid 的进程），不含自己；sudo 父进程是 root 的，
// 不受影响。同一台机器上 builder 只给执行进程用，所以这是安全的。
func reap(who identity) {
	if !who.separated {
		return
	}
	_ = syscall.Kill(-1, syscall.SIGKILL)
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		sweepOwned(dir, who.uid)
	}
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
