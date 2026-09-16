package backupbundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Helix2010/RN-Server/internal/backupcontainer"
)

// 这是整个改动里最重要的一条测试。
//
// 灾难当天走的不是我们的代码，是**备份包旁边那份 README-FIRST.txt 里印的那段
// 脚本**。它跑不通，前面所有东西都是废的——而 Go 封 Go 解的往返测试**发现不了**
// 这一点：漏写 PKCS#7 填充、MAC 覆盖范围写错、三层文件名互相覆盖，这些都只在
// openssl 那条路上炸。
//
// 所以这里不凭记忆敲命令：从生成出来的 README 正文里把那段脚本抠出来，去掉缩进，
// 照它自己写的用法跑三遍。README 的正文变了这条测试就得跟着变，而那正是我们要的
// ——那几条命令是产品的一部分。
func TestGeneratedReadmeScriptActuallyOpensThePackage(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is not installed; skipping the end-to-end recovery check")
	}
	if _, err := os.Stat("/dev/shm"); err != nil {
		t.Skip("/dev/shm is not available; the generated script stages secrets there")
	}

	holders := testHolders(t)
	in, signingPub := testInputWithSigner(t, holders)
	// 放一个人一眼能认出来的标记，证明我们真的解到了内层明文
	marker := "THE-SIGNING-KEY-MADE-IT-THROUGH"
	in.ServerFiles["rn-foundation.env"] = []byte("STORAGE_MASTER_KEY=" + marker + "\n")

	sink := newSink()
	packages, err := Assemble(in, sink)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}

	dir := t.TempDir()
	// 三把私钥落成 PEM，模拟三个持有人手上那份
	keyPaths := map[string]string{}
	for _, h := range holders {
		path := filepath.Join(dir, h.slot+".key")
		der, err := x509.MarshalPKCS8PrivateKey(h.key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path,
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		keyPaths[h.slot] = path
	}

	for _, pkg := range packages {
		pair := pairByName(t, pkg.Pair)

		// 1) 把包落盘，并核对 README 里印的 sha256 ——这是 README 的第一步
		pkgPath := filepath.Join(dir, "backup-"+pkg.Pair+".rnbk")
		body := sink.packages[pkg.Pair].Bytes()
		if err := os.WriteFile(pkgPath, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := sha256Hex(body); got != pkg.SHA256 {
			t.Fatalf("%s: README 里印的 sha256 和对象本身对不上", pkg.Pair)
		}
		if !strings.Contains(pkg.ReadmeFirst, pkg.SHA256) {
			t.Fatalf("%s: README 里没有印 sha256", pkg.Pair)
		}

		// 2) 从 README 正文里抠出那段脚本，**不是从常量里抠**——要测的正是
		//    印给人看的那一份
		script := extractOpenLayerScript(t, pkg.ReadmeFirst)
		scriptPath := filepath.Join(dir, "open-layer.sh")
		if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}

		// 3) 照 README 写的顺序跑三遍：先外层那个人，再内层那个人
		out := filepath.Join(dir, "out-"+pkg.Pair)
		runScript(t, scriptPath, pkgPath, keyPaths[pair.Outer], filepath.Join(out, "L1"))
		runScript(t, scriptPath, filepath.Join(out, "L1", "inner.rnbk"),
			keyPaths[pair.Inner], filepath.Join(out, "L2-agent"))
		runScript(t, scriptPath, filepath.Join(out, "L1", "server.rnbk"),
			keyPaths[pair.Inner], filepath.Join(out, "L2-server"))

		// 4) 内层明文里那个标记必须在
		env, err := os.ReadFile(filepath.Join(out, "L2-server", "rn-foundation.env"))
		if err != nil {
			t.Fatalf("%s: 解到底之后没拿到服务端配置: %v", pkg.Pair, err)
		}
		if !strings.Contains(string(env), marker) {
			t.Fatalf("%s: 解出来的内容不对", pkg.Pair)
		}
		// 外层那三份说明也要在，而且 RECOVERY.md 要带真实值不是模板
		recovery, err := os.ReadFile(filepath.Join(out, "L1", "RECOVERY.md"))
		if err != nil {
			t.Fatalf("%s: 没有 RECOVERY.md: %v", pkg.Pair, err)
		}
		if strings.Contains(string(recovery), "<租户>") || strings.Contains(string(recovery), "<域名>") {
			t.Fatalf("%s: RECOVERY.md 里还留着模板占位符", pkg.Pair)
		}
		for _, want := range []string{"acme", "13080", "x-admin-key", "build-agent show-key"} {
			if !strings.Contains(string(recovery), want) {
				t.Fatalf("%s: RECOVERY.md 里没有 %q——恢复的人会卡在这一步", pkg.Pair, want)
			}
		}

		// 5) 验签：照 README 第四步跑，然后确认改一位就验不过
		verifySignature(t, openssl, dir, signingPub, out)
	}
}

// extractOpenLayerScript 把 README 正文里那段脚本原样抠出来并去掉缩进——
// 正是一个人「复制粘贴存成 open-layer.sh」会做的事
func extractOpenLayerScript(t *testing.T, readme string) string {
	t.Helper()
	start := strings.Index(readme, "    #!/bin/bash")
	if start < 0 {
		t.Fatal("README 里找不到那段脚本")
	}
	end := strings.Index(readme[start:], `echo "OK -> $OUT"`)
	if end < 0 {
		t.Fatal("README 里那段脚本没有结尾")
	}
	block := readme[start : start+end+len(`echo "OK -> $OUT"`)]
	lines := strings.Split(block, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimPrefix(line, "    ")
	}
	return strings.Join(lines, "\n") + "\n"
}

func runScript(t *testing.T, script, pkg, key, out string) {
	t.Helper()
	cmd := exec.Command("bash", script, pkg, key, out)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("README 里那段脚本跑不通\n  包: %s\n  错误: %v\n  stdout:\n%s\n  stderr:\n%s",
			filepath.Base(pkg), err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "OK -> ") {
		t.Fatalf("脚本没有报成功: %s", stdout.String())
	}
}

// verifySignature 跑 README 第四步那两条命令，并确认改一位就验不过——
// 否则「验签通过之前不要跑 recover.sh」这条约束是空的
func verifySignature(t *testing.T, openssl, dir string, signingPub ed25519.PublicKey, out string) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(signingPub)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "signing.pem")
	if err := os.WriteFile(pubPath,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(out, "L1", "inner.rnbk")
	sig := filepath.Join(out, "L1", "inner.rnbk.sig")
	cmd := exec.Command(openssl, "pkeyutl", "-verify", "-pubin", "-inkey", pubPath,
		"-rawin", "-in", inner, "-sigfile", sig)
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "Success") {
		t.Fatalf("README 第四步的验签命令没通过: %v\n%s", err, output)
	}

	// 改一位
	body, err := os.ReadFile(inner)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 0x01
	tampered := filepath.Join(out, "tampered.rnbk")
	if err := os.WriteFile(tampered, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(openssl, "pkeyutl", "-verify", "-pubin", "-inkey", pubPath,
		"-rawin", "-in", tampered, "-sigfile", sig)
	if err := cmd.Run(); err == nil {
		t.Fatal("改了一位的内层密文竟然通过了验签")
	}
}

func pairByName(t *testing.T, name string) backupcontainer.Pair {
	t.Helper()
	for _, pair := range backupcontainer.Pairs() {
		if pair.Name == name {
			return pair
		}
	}
	t.Fatalf("不认识的配对 %s", name)
	return backupcontainer.Pair{}
}

// 生成出来的两个脚本必须语法正确。
//
// 它们是**渲染**出来的，不是仓库里的静态文件——一个拼错的引号、一个没闭合的
// heredoc，要到灾难当天有人跑它时才暴露，而那时没有第二次机会。bash -n 只查
// 语法不执行，几毫秒的事。
func TestGeneratedScriptsAreSyntacticallyValid(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}
	holders := testHolders(t)
	in := testInput(t, holders)
	dir := t.TempDir()

	for _, pair := range backupcontainer.Pairs() {
		for name, body := range map[string]string{
			"recover.sh":    renderRecoverScript(in, pair),
			"open-layer.sh": extractOpenLayerScript(t, renderReadmeFirst(in, pair, recipientMap(in), "deadbeef")),
		} {
			path := filepath.Join(dir, pair.Name+"-"+name)
			if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", "-n", path)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s（%s 组）语法不对——灾难当天才会发现:\n%s", name, pair.Name, output)
			}
		}
	}
}

// README 必须教人解到**内存盘**，不是当前目录。
//
// open-layer.sh 自己在 tmpfs 上做解密，但最后一步 `tar xf plain.tar -C "$OUT"`
// 会把明文拷到调用者指定的目录——README 要是示范 ./L1，全平台每个租户的签名
// 密钥明文就留在某人的工作目录里，而 SSD 上 rm 不等于擦除。
func TestReadmeTellsYouToExtractOntoRamAndDestroyAfterwards(t *testing.T) {
	holders := testHolders(t)
	in := testInput(t, holders)
	readme := renderReadmeFirst(in, backupcontainer.Pairs()[0], recipientMap(in), "deadbeef")

	for _, want := range []string{"/dev/shm", "rm -rf"} {
		if !strings.Contains(readme, want) {
			t.Fatalf("README 里没有 %q——明文会留在某人的工作目录里", want)
		}
	}
	if strings.Contains(readme, "key  ./L1") {
		t.Fatal("README 还在示范解到当前目录")
	}
}

// recover.sh 结束时必须提醒销毁解出来的明文。
//
// 它不替你做是有意的：万一还没装完就被清掉，恢复要从头再来一遍，那在灾难当天
// 很贵。但它必须说——不说的话，那份明文会一直留着。
func TestRecoverScriptRemindsYouToDestroyThePlaintext(t *testing.T) {
	holders := testHolders(t)
	script := renderRecoverScript(testInput(t, holders), backupcontainer.Pairs()[0])
	for _, want := range []string{"别忘了销毁", "rm -rf", "umask 077"} {
		if !strings.Contains(script, want) {
			t.Fatalf("recover.sh 里没有 %q", want)
		}
	}
}

func recipientMap(in Input) map[string]Recipient {
	out := map[string]Recipient{}
	for _, r := range in.Recipients {
		out[r.Slot] = r
	}
	return out
}
