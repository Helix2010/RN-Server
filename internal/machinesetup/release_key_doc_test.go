package machinesetup

// 运维手册里「当前这一把」那张表记着发布公钥的指纹，装机时人从密码管理器取的就是它，
// 而这张表是以后别人查"当前是哪把"的地方。
//
// 它必须和仓库里的 release-key.pub 是同一把。靠人记得同步是不够的——换密钥的人只会想到
// 改公钥文件，这件事在 2026-09-19 那天连着漏了两次。漂了之后的症状是：有人照文档里的旧
// 指纹去装机，脚本报"确认手里的值取自密码管理器"，把人往抄错了的方向引，没人会怀疑文档。

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestReleaseKeyTableMatchesTheDeployedKey(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/build-agent-macos/release-key.pub")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(strings.TrimSpace(string(raw)))
	if len(fields) < 2 || fields[0] != "ssh-ed25519" {
		t.Fatalf("release-key.pub is not an ssh-ed25519 public key line: %q", raw)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		t.Fatalf("release-key.pub is not base64: %v", err)
	}
	// SSH blob 是 4B 长度 + "ssh-ed25519" + 4B 长度 + 32B 公钥，共 51 字节；末 32 字节是公钥。
	// 指纹算的是那 32 字节，不是这个文件——与 bundle-sign、签名里的 publicKeySha256、控制台
	// 三处一致（口径不一致曾经让装机必然失败，见提交 b01a11d）
	if len(blob) != 51 {
		t.Fatalf("release-key.pub carries %d bytes, expected a 51-byte ssh-ed25519 blob", len(blob))
	}
	sum := sha256.Sum256(blob[len(blob)-32:])
	want := hex.EncodeToString(sum[:])

	doc, err := os.ReadFile("../../deploy/build-agent-macos/SIGNING_MATERIAL.md")
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(doc), "### 3.0 当前这一把")
	if !ok {
		t.Fatal("SIGNING_MATERIAL.md has no 「当前这一把」 section")
	}
	table, _, _ := strings.Cut(after, "\n\n在它之前")
	if !strings.Contains(table, want) {
		t.Fatalf("SIGNING_MATERIAL.md §3.0 does not name the deployed release key %s.\n"+
			"换密钥时 release-key.pub 与这张表要在同一个提交里改：表里留着旧指纹的话，"+
			"照它装机会失败，而报错说的是「确认手里的值取自密码管理器」，没人会怀疑文档。\n%s", want, table)
	}
}
