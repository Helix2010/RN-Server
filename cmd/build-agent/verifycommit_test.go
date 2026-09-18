package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 提交签名校验（设计 ios-mac-builders-home-network-2026-09-18 §4.6）。
//
// 这台 Mac 上放着全部租户的签名材料，而它构建的是服务端指过来的那个提交。没有这道闸，
// 任何一条通向"能改 main"或"能改服务端数据库"的路，都直接等于"在这台机器上执行任意
// 代码"——也就等于拿到全部租户的 Distribution 私钥。

// signingRepo 造一个用 SSH 密钥签提交的仓库，返回仓库路径、允许签名者文件、
// 已签名与未签名的两个提交。
func signingRepo(t *testing.T) (repo, allowedSigners, signed, unsigned string) {
	t.Helper()
	root := t.TempDir()
	// t.TempDir 建出来的目录是 0775：名单文件所在的目录组可写，checkPinnedFile 会拒——
	// 而它拒得对（目录可写的话，换掉整个文件只是一次 rename）
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	repo = filepath.Join(root, "src")
	key := filepath.Join(root, "signer")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "builder@example.com", "-f", key).CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen is not usable here: %v %s", err, out)
	}
	public, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	allowedSigners = filepath.Join(root, "allowed_signers")
	if err := os.WriteFile(allowedSigners, []byte("builder@example.com "+string(public)), 0o644); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_AUTHOR_NAME=Builder", "GIT_AUTHOR_EMAIL=builder@example.com",
			"GIT_COMMITTER_NAME=Builder", "GIT_COMMITTER_EMAIL=builder@example.com")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v %s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	git("init", "-q", "-b", "main")
	git("config", "gpg.format", "ssh")
	git("config", "user.signingkey", key)
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-q", "-S", "-m", "signed")
	signed = git("rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-q", "--no-gpg-sign", "-m", "unsigned")
	unsigned = git("rev-parse", "HEAD")
	return repo, allowedSigners, signed, unsigned
}

func signingAgent(t *testing.T, allowedSigners string) *agent {
	t.Helper()
	a := &agent{cfg: config{AllowedSigners: allowedSigners, MachineEnv: map[string]string{"PATH": os.Getenv("PATH")}},
		pinnedFilesOwner: os.Geteuid()}
	return a
}

func TestVerifyCommitAcceptsOnlyAnAllowedSigner(t *testing.T) {
	repo, allowedSigners, signed, unsigned := signingRepo(t)
	a := signingAgent(t, allowedSigners)
	buf := newLogBuffer(newRedactor())
	if err := a.verifyCommitSignature(context.Background(), repo, signed, buf); err != nil {
		t.Fatalf("a commit signed by an allowed signer was refused: %v", err)
	}
	// 未签名的提交：推得上去也构建不了
	err := a.verifyCommitSignature(context.Background(), repo, unsigned, buf)
	if err == nil || !strings.Contains(err.Error(), "not signed by an allowed signer") {
		t.Fatalf("an unsigned commit was accepted: %v", err)
	}
	// 签名者不在名单里：换一份空名单，同一个提交就该被拒
	otherRoot := t.TempDir()
	if err := os.Chmod(otherRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(otherRoot, "allowed_signers")
	if err := os.WriteFile(empty, []byte("nobody@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a.cfg.AllowedSigners = empty
	if err := a.verifyCommitSignature(context.Background(), repo, signed, buf); err == nil {
		t.Fatal("a signature from a key outside allowed_signers was accepted")
	}
}

// 名单文件本身必须是控制进程改不了的：能改它就等于能把自己加进去。
func TestVerifyCommitRefusesAWritableAllowedSignersFile(t *testing.T) {
	repo, allowedSigners, signed, _ := signingRepo(t)
	a := signingAgent(t, allowedSigners)
	buf := newLogBuffer(newRedactor())
	if err := os.Chmod(allowedSigners, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := a.verifyCommitSignature(context.Background(), repo, signed, buf); err == nil ||
		!strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("a world-writable allowed_signers file was accepted: %v", err)
	}
	if err := os.Chmod(allowedSigners, 0o644); err != nil {
		t.Fatal(err)
	}
	a.pinnedFilesOwner = os.Geteuid() + 1
	if err := a.verifyCommitSignature(context.Background(), repo, signed, buf); err == nil ||
		!strings.Contains(err.Error(), "must belong to root") {
		t.Fatalf("an allowed_signers file owned by the agent itself was accepted: %v", err)
	}
}

// 没配这个键就是没开这道闸：Android 构建机今天就是这么跑的，不能因为加了新功能就不启动。
func TestVerifyCommitIsOffWhenNoAllowedSignersFileIsConfigured(t *testing.T) {
	repo, _, _, unsigned := signingRepo(t)
	a := signingAgent(t, "")
	if err := a.verifyCommitSignature(context.Background(), repo, unsigned, newLogBuffer(newRedactor())); err != nil {
		t.Fatalf("verification ran without a configured allowed_signers file: %v", err)
	}
}
