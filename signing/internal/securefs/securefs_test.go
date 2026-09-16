//go:build linux || darwin

package securefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckPrivate(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateDir(dir); err != nil {
		t.Fatalf("private dir rejected: %v", err)
	}
	file := filepath.Join(dir, "key")
	if err := WriteFileExclusive(file, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateFile(file); err != nil {
		t.Fatalf("private file rejected: %v", err)
	}
	if err := WriteFileExclusive(file, []byte("again")); err == nil {
		t.Fatal("WriteFileExclusive overwrote a file")
	}
	got, err := ReadPrivateFile(file, 64)
	if err != nil || string(got) != "secret" {
		t.Fatalf("ReadPrivateFile = %q, %v", got, err)
	}
	if _, err := ReadPrivateFile(file, 3); err == nil {
		t.Fatal("ReadPrivateFile ignored the size limit")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateFile(link); err == nil {
		t.Fatal("accepted a symlink")
	}
	if _, err := ReadPrivateFile(link, 64); err == nil {
		t.Fatal("read through a symlink")
	}
	if err := os.Chmod(file, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateFile(file); err == nil {
		t.Fatal("accepted a group-readable file")
	}
	if err := CheckPrivateDir(file); err == nil {
		t.Fatal("accepted a file as a directory")
	}
	if err := CheckPrivateFile("relative/path"); err == nil {
		t.Fatal("accepted a relative path")
	}
	open := filepath.Join(dir, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateDir(open); err == nil {
		t.Fatal("accepted a world-readable directory")
	}
	if err := EnsurePrivateDir(filepath.Join(dir, "sub")); err != nil {
		t.Fatalf("EnsurePrivateDir: %v", err)
	}
}

func TestCheckTrustedPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	java := filepath.Join(bin, "java")
	if err := os.WriteFile(java, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(java, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckTrustedPath(java); err != nil {
		t.Fatalf("trusted file rejected: %v", err)
	}
	link := filepath.Join(dir, "java-link")
	if err := os.Symlink(java, link); err != nil {
		t.Fatal(err)
	}
	if err := CheckTrustedPath(link); err != nil {
		t.Fatalf("symlink to a trusted file rejected: %v", err)
	}
	if err := os.Chmod(bin, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := CheckTrustedPath(java); err == nil {
		t.Fatal("accepted a file inside a group-writable directory")
	}
	if err := CheckTrustedPath(link); err == nil {
		t.Fatal("accepted a symlink whose target sits in a group-writable directory")
	}
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(java, 0o757); err != nil {
		t.Fatal(err)
	}
	if err := CheckTrustedPath(java); err == nil {
		t.Fatal("accepted a world-writable file")
	}
	if err := CheckTrustedPath("relative/java"); err == nil {
		t.Fatal("accepted a relative path")
	}
	if err := CheckTrustedPath("/usr/bin/env"); err != nil {
		t.Fatalf("a root-owned system binary was rejected: %v", err)
	}
}

func TestCheckTrustedTree(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.Chmod(root, 0o755))
	jdk := filepath.Join(root, "jdk")
	lib := filepath.Join(jdk, "lib", "server")
	must(os.MkdirAll(lib, 0o755))
	must(os.Chmod(filepath.Join(jdk, "lib"), 0o755))
	must(os.Chmod(lib, 0o755))
	must(os.Chmod(jdk, 0o755))
	so := filepath.Join(lib, "libjvm.so")
	must(os.WriteFile(so, []byte("elf"), 0o644))
	must(os.Chmod(so, 0o644))
	must(os.Symlink("/usr/bin/env", filepath.Join(jdk, "lib", "outside")))
	must(os.Symlink(filepath.Join(root, "missing"), filepath.Join(jdk, "lib", "dangling")))
	if err := CheckTrustedTree(jdk); err != nil {
		t.Fatalf("trusted tree rejected: %v", err)
	}
	// 树深处一个组可写的库文件就足以在签名闸里执行任意代码
	must(os.Chmod(so, 0o664))
	if err := CheckTrustedTree(jdk); err == nil {
		t.Fatal("accepted a group-writable library deep inside the tree")
	}
	must(os.Chmod(so, 0o644))
	untrusted := filepath.Join(root, "untrusted")
	must(os.Mkdir(untrusted, 0o777))
	must(os.Chmod(untrusted, 0o777))
	must(os.WriteFile(filepath.Join(untrusted, "java.security"), []byte("x"), 0o644))
	must(os.Symlink(filepath.Join(untrusted, "java.security"), filepath.Join(jdk, "lib", "security")))
	if err := CheckTrustedTree(jdk); err == nil {
		t.Fatal("accepted a symlink into a world-writable directory")
	}
}

func TestCheckTmpfs(t *testing.T) {
	if err := CheckTmpfs("/proc"); err == nil {
		t.Fatal("/proc reported as tmpfs")
	}
	if err := CheckTmpfs("/dev/shm"); err != nil {
		t.Skipf("no tmpfs at /dev/shm on this machine: %v", err)
	}
}

func TestRemoveContentsAndLocks(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a", "b/c"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := RemoveContents(dir); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("RemoveContents left %d entries", len(entries))
	}
	path := filepath.Join(dir, "lock")
	a, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if ok, err := TryLock(a); !ok || err != nil {
		t.Fatalf("first TryLock = %v, %v", ok, err)
	}
	if ok, _ := TryLock(b); ok {
		t.Fatal("second TryLock succeeded while the first is held")
	}
	if err := Unlock(a); err != nil {
		t.Fatal(err)
	}
	if ok, err := TryLock(b); !ok || err != nil {
		t.Fatalf("TryLock after unlock = %v, %v", ok, err)
	}
}
