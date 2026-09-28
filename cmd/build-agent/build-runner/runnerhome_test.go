package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// 执行账户跨任务可写的家目录按白名单清空（runnerhome.go）：上一个租户的描述文件不能留给下一个，
// Xcode 自己的缓存留着；本地测试时（不是分离的 uid）绝不碰。

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func TestRunnerHomeKeepsOnlyTheXcodeCache(t *testing.T) {
	home := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.txt")
	writeFile(t, outside, "must survive")
	writeFile(t, filepath.Join(home, "Library/Caches/com.apple.dt.Xcode/cache.db"), "index")
	writeFile(t, filepath.Join(home, "Library/Caches/org.cocoapods/pod.tgz"), "shared cache")
	writeFile(t, filepath.Join(home, "Library/MobileDevice/Provisioning Profiles/UUID.mobileprovision"), "tenant A profile")
	writeFile(t, filepath.Join(home, "Library/Developer/Xcode/UserData/Provisioning Profiles/UUID.mobileprovision"), "tenant A profile")
	writeFile(t, filepath.Join(home, ".npmrc"), "left by a job")
	if err := os.Symlink(outside, filepath.Join(home, "link")); err != nil {
		t.Fatal(err)
	}

	who := identity{uid: os.Getuid(), sudoUID: os.Getuid() + 1, separated: true}
	if err := pruneAccountHome(io.Discard, who, home); err != nil {
		t.Fatal(err)
	}
	if !exists(filepath.Join(home, "Library/Caches/com.apple.dt.Xcode/cache.db")) {
		t.Fatal("the Xcode cache must be kept")
	}
	for _, gone := range []string{
		"Library/Caches/org.cocoapods",
		"Library/MobileDevice",
		"Library/Developer",
		".npmrc",
		"link",
	} {
		if exists(filepath.Join(home, gone)) {
			t.Fatalf("%s survived the cleanup", gone)
		}
	}
	// 符号链接只删链接，不跟进去删它指向的东西
	if !exists(outside) {
		t.Fatal("the cleanup followed a symlink out of the home")
	}
	// 再清一次什么都不做
	if err := pruneAccountHome(io.Discard, who, home); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerHomeIsLeftAloneOutsideProduction(t *testing.T) {
	home := t.TempDir()
	profile := filepath.Join(home, "Library/MobileDevice/Provisioning Profiles/UUID.mobileprovision")
	writeFile(t, profile, "developer's own profile")

	// 本地测试（执行进程与控制进程同一个 uid）：密码数据库里的家就是开发者自己的家
	if err := pruneRunnerHome(io.Discard, identity{uid: os.Getuid(), sudoUID: -1}); err != nil {
		t.Fatal(err)
	}
	// 不属于执行账户的目录不清
	if err := pruneAccountHome(io.Discard, identity{uid: os.Getuid() + 1, separated: true}, home); err != nil {
		t.Fatal(err)
	}
	// 根目录与 /var/empty 这种一律不碰
	for _, dangerous := range []string{"/", "/var/empty", "relative/home"} {
		if err := pruneAccountHome(io.Discard, identity{uid: os.Getuid(), separated: true}, dangerous); err != nil {
			t.Fatalf("%s: %v", dangerous, err)
		}
	}
	if !exists(profile) {
		t.Fatal("a home that is not the runner's own was cleaned")
	}
}
