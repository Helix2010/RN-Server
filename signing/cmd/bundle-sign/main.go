// bundle-sign 是安装包清单的离线签名工具，只在不联网的离线机器上运行。
//
//	bundle-sign key create --out <目录>            生成发布密钥（全平台只做一次）
//	bundle-sign key public --key <私钥>            从私钥重新打印公钥与它的指纹
//	bundle-sign sign --key <私钥> --dir <安装包目录> --sequence <n>
//	bundle-sign verify --pub <公钥> --dir <安装包目录> [--min-sequence <n>] [--expect-commit <sha>]
//
// 为什么要有这一步（设计 docs/design/ios-mac-builders-home-network-2026-09-18.md §5.6）：
// 自升级是唯一一条"服务端能往每台 Mac 上放可执行代码"的路，而每台 Mac 上放着全部租户的
// 签名材料。只校验 sha256 挡不住服务端被攻破——那个 sha256 也是服务端给的。所以清单要由
// 一把**服务端手里没有**的私钥签过，私钥只在这台离线机器与密码管理器里。
//
// 签名覆盖提交、单调序号与清单摘要。要回滚到旧版本，就用更高的序号再签一份指向旧提交的
// 清单：回滚是一次显式的、有签名的动作，不是数据库里改一个值。
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Helix2010/RN-Server/signing/bundlesig"
)

// manifestName 与 build-bundles.sh 产出的文件名一致。
const manifestName = "manifest.json"

// releaseKeyComment 是公钥行末尾的注释，只为了人看着知道这是哪一把。
const releaseKeyComment = "rn-release-key"

// maxManifestSize：清单是几十 KB 的 JSON（每个文件一条）。
const maxManifestSize = 4 << 20

var now = time.Now

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "key":
		if len(args) >= 2 && args[1] == "create" {
			return createKey(args[2:], stdout, stderr)
		}
		if len(args) >= 2 && args[1] == "public" {
			return publicKey(args[2:], stdout, stderr)
		}
	case "sign":
		return sign(args[1:], stdout, stderr)
	case "verify":
		return verify(args[1:], stdout, stderr)
	}
	usage(stderr)
	return 2
}

func usage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage:")
	fmt.Fprintln(stderr, "  bundle-sign key create --out <dir>")
	fmt.Fprintln(stderr, "  bundle-sign key public --key <private key file>")
	fmt.Fprintln(stderr, "  bundle-sign sign --key <private key file> --dir <bundle dir> --sequence <n>")
	fmt.Fprintln(stderr, "  bundle-sign verify --pub <public key file> --dir <bundle dir> [--min-sequence <n>] [--expect-commit <sha>]")
}

// createKey 生成发布密钥。私钥写 0600，公钥与它的 sha256 打到屏幕上——那个 sha256 是
// 装机时在每台 Mac 上核对 /opt/rn-build-agent/release-key.pub 用的，要记进密码管理器。
func createKey(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("key create", flag.ContinueOnError)
	set.SetOutput(stderr)
	out := set.String("out", "", "directory to write the key pair into")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || *out == "" {
		fmt.Fprintln(stderr, "usage: bundle-sign key create --out <dir>")
		return 2
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(stderr, "cannot generate a release key:", err)
		return 1
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	privatePath := filepath.Join(*out, "release-key.ed25519")
	publicPath := filepath.Join(*out, "release-key.pub")
	// 私钥用 O_EXCL 写：已经有一把的时候宁可失败，也不要在一台离线机器上悄悄盖掉
	// 那把签过历史清单的密钥
	file, err := os.OpenFile(privatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintln(stderr, "cannot write the private key (does it already exist?):", err)
		return 1
	}
	_, err = io.WriteString(file, base64.StdEncoding.EncodeToString(private)+"\n")
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := os.WriteFile(publicPath, []byte(bundlesig.SSHPublicKeyLine(public, releaseKeyComment)+"\n"), 0o644); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "private key: %s (0600, keep it offline and in the password manager)\n", privatePath)
	fmt.Fprintf(stdout, "public key:  %s\n", publicPath)
	fmt.Fprintf(stdout, "public key sha256: %s\n", bundlesig.PublicKeySHA256(public))
	fmt.Fprintln(stdout, "write that sha256 into the password manager: every machine installation checks it out of band.")
	return 0
}

// publicKey 从私钥重新导出公钥：
//
//	bundle-sign key public --key release-key.ed25519 > release-key.pub
//
// 有了它，换公钥文件格式这种事不需要动私钥，也不需要把私钥从密码管理器里搬到别处去——
// 在那台离线机器上跑一条命令就行。
func publicKey(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("key public", flag.ContinueOnError)
	set.SetOutput(stderr)
	keyPath := set.String("key", "", "release private key file")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || *keyPath == "" {
		fmt.Fprintln(stderr, "usage: bundle-sign key public --key <private key file>")
		return 2
	}
	keyRaw, err := os.ReadFile(*keyPath)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read the release private key:", err)
		return 1
	}
	private, err := bundlesig.ParsePrivateKey(keyRaw)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	public, _ := private.Public().(ed25519.PublicKey)
	// 公钥行走 stdout，说明走 stderr：`bundle-sign key public --key … > release-key.pub`
	// 就是完整的用法，不用再 head -1
	fmt.Fprintln(stdout, bundlesig.SSHPublicKeyLine(public, releaseKeyComment))
	fmt.Fprintf(stderr, "public key sha256: %s\n", bundlesig.PublicKeySHA256(public))
	fmt.Fprintln(stderr, "redirect stdout into release-key.pub; the sha256 is what every installation checks out of band.")
	return 0
}

func sign(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("sign", flag.ContinueOnError)
	set.SetOutput(stderr)
	keyPath := set.String("key", "", "release private key file")
	dir := set.String("dir", "", "bundle directory that holds manifest.json")
	sequence := set.Int64("sequence", 0, "signature sequence number; must be higher than every earlier one")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || *keyPath == "" || *dir == "" || *sequence < 1 {
		fmt.Fprintln(stderr, "usage: bundle-sign sign --key <private key file> --dir <bundle dir> --sequence <n>")
		return 2
	}
	keyRaw, err := os.ReadFile(*keyPath)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read the release private key:", err)
		return 1
	}
	private, err := bundlesig.ParsePrivateKey(keyRaw)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	manifest, commit, err := readManifest(*dir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	signature, err := bundlesig.Sign(private, manifest, commit, *sequence, now())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	encoded, err := json.MarshalIndent(signature, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	path := filepath.Join(*dir, bundlesig.FileName)
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "signed %s\n", path)
	fmt.Fprintf(stdout, "commit:   %s\n", signature.Commit)
	fmt.Fprintf(stdout, "sequence: %d\n", signature.Sequence)
	fmt.Fprintf(stdout, "release key sha256: %s\n", signature.PublicKeySHA256)
	return 0
}

func verify(args []string, stdout, stderr io.Writer) int {
	set := flag.NewFlagSet("verify", flag.ContinueOnError)
	set.SetOutput(stderr)
	pubPath := set.String("pub", "", "release public key file")
	dir := set.String("dir", "", "bundle directory that holds manifest.json and manifest.sig")
	minSequence := set.Int64("min-sequence", 0, "refuse a signature whose sequence is below this")
	expectCommit := set.String("expect-commit", "", "refuse a signature for another commit")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || *pubPath == "" || *dir == "" {
		fmt.Fprintln(stderr, "usage: bundle-sign verify --pub <public key file> --dir <bundle dir> [--min-sequence <n>] [--expect-commit <sha>]")
		return 2
	}
	pubRaw, err := os.ReadFile(*pubPath)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read the release public key:", err)
		return 1
	}
	public, err := bundlesig.ParsePublicKey(pubRaw)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	manifest, _, err := readManifest(*dir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	sigRaw, err := os.ReadFile(filepath.Join(*dir, bundlesig.FileName))
	if err != nil {
		fmt.Fprintln(stderr, "cannot read the signature:", err)
		return 1
	}
	signature, err := bundlesig.Parse(sigRaw)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := bundlesig.Verify(public, manifest, signature); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *minSequence > 0 && signature.Sequence < *minSequence {
		fmt.Fprintf(stderr, "sequence %d is below %d: this manifest is older than one this machine already accepted\n",
			signature.Sequence, *minSequence)
		return 1
	}
	if *expectCommit != "" && signature.Commit != *expectCommit {
		fmt.Fprintf(stderr, "the signed manifest is for commit %s, not %s\n", signature.Commit, *expectCommit)
		return 1
	}
	fmt.Fprintf(stdout, "signature is valid: commit %s, sequence %d, release key sha256 %s\n",
		signature.Commit, signature.Sequence, signature.PublicKeySHA256)
	return 0
}

// readManifest 读清单并取出它声明的提交。
func readManifest(dir string) (raw []byte, commit string, err error) {
	path := filepath.Join(dir, manifestName)
	info, err := os.Stat(path)
	if err != nil {
		return nil, "", fmt.Errorf("cannot read %s: %w", path, err)
	}
	if info.Size() > maxManifestSize {
		return nil, "", fmt.Errorf("%s is %d bytes, too large to be a bundle manifest", path, info.Size())
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var doc struct {
		Format string `json:"format"`
		Commit string `json:"commit"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, "", fmt.Errorf("%s is not JSON: %w", path, err)
	}
	if doc.Format != "rn-machine-bundles/v1" {
		return nil, "", fmt.Errorf("%s has format %q, which this tool does not sign", path, doc.Format)
	}
	if doc.Commit == "" {
		return nil, "", fmt.Errorf("%s names no commit", path)
	}
	return raw, doc.Commit, nil
}
