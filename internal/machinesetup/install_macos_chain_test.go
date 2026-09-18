package machinesetup

// 这个文件把 install-macos.sh 里那条信任链真的跑一遍。
//
// 为什么不能只靠"脚本里有没有这几行"那种形状检查：这条链子上一处口径不一致就会让**每一
// 次装机都失败**，而且失败信息会说"安装包被换过"，把人往"遭到攻击"上引。上一版就踩过——
// 脚本按 release-key.pub 这个**文件**算 sha256，而 bundle-sign、签名里的 publicKeySha256
// 与控制台算的都是**公钥字节**的 sha256，两边永远对不上。形状检查全绿，装机一台也装不上。
//
// 所以这里按服务端真会回的样子造一份 describe 响应，用真的发布密钥签一份真的清单，再把
// 脚本里的 parse_description 拉出来跑，正反面都走一遍。

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crypto/ed25519"
	"crypto/rand"

	"github.com/Helix2010/RN-Server/signing/bundlesig"
)

// chainTools 是脚本在验签之前用到的外部程序。少一个就跳过：这个测试盯的是链子的口径，
// 不该变成对构建环境的要求。
func chainTools(t *testing.T) {
	t.Helper()
	for _, path := range []string{"/usr/bin/shasum", "/usr/bin/openssl"} {
		if _, err := os.Stat(path); err != nil {
			t.Skipf("no %s on this machine", path)
		}
	}
	for _, name := range []string{"ssh-keygen", "python3", "bash"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("no %s on this machine", name)
		}
	}
}

const chainCommit = "0123456789abcdef0123456789abcdef01234567"

// chainManifest 造一份 build-bundles.sh 会产出的清单。
func chainManifest(archiveSHA string) []byte {
	manifest := map[string]any{
		"format": "rn-machine-bundles/v1",
		"commit": chainCommit,
		"bundles": map[string]any{
			"builder-darwin-arm64": map[string]any{
				"archive": "builder-darwin-arm64.tar.gz", "archiveSha256": archiveSHA, "archiveSize": 4242,
				"files": []any{
					map[string]any{"name": "bin/build-agent", "size": 1, "sha256": strings.Repeat("c", 64)},
					map[string]any{"name": "allowed_signers", "size": 2, "sha256": strings.Repeat("d", 64)},
				},
			},
		},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		panic(err)
	}
	return raw
}

// writeDescribe 造一份 describe 响应。
func writeDescribe(t *testing.T, path string, keyLine string, manifest []byte, signature any) {
	t.Helper()
	doc := map[string]any{
		"role": "builder", "os": "darwin", "name": "mac-01",
		"releaseKeyPub":  keyLine,
		"manifestBase64": base64.StdEncoding.EncodeToString(manifest),
		"bundle": map[string]any{"archive": "builder-darwin-arm64.tar.gz",
			"archiveSha256": strings.Repeat("b", 64), "archiveSize": 4242},
	}
	if signature != nil {
		doc["manifestSignature"] = signature
	}
	if manifest == nil {
		doc["manifestBase64"] = nil
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// runChain 把脚本里的 parse_description 拉出来单独跑。脚本开头会 cd / 、重置 PATH、
// unset 掉所有函数与导出变量（它就该这么做），所以路径一律写绝对的。
func runChain(t *testing.T, dir, describe, keySHA string) (string, error) {
	t.Helper()
	harness := fmt.Sprintf(`set -u
D=%q
sed '/^main "\$@"$/d; /^exit$/d' "$D/install-macos.sh" > "$D/lib.sh"
(
  set --
  . "$D/lib.sh"
  cd "$D"
  WORK="$(mktemp -d "$D/work.XXXXXX")"
  RELEASE_KEY_SHA256=%q
  parse_description %q
  printf 'RESULT %%s %%s %%s\n' "$BUNDLE_COMMIT" "$BUNDLE_SEQUENCE" "$BUNDLE_SHA256"
)
`, dir, keySHA, filepath.Join(dir, describe))
	cmd := exec.Command("bash", "-c", harness)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// chainFixture 备好一个目录：脚本、发布密钥、签过的清单。
func chainFixture(t *testing.T) (dir string, public ed25519.PublicKey, private ed25519.PrivateKey, manifest []byte, signature bundlesig.Signature) {
	t.Helper()
	chainTools(t)
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "install-macos.sh"), InstallMacOSScript, 0o700); err != nil {
		t.Fatal(err)
	}
	var err error
	public, private, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest = chainManifest(strings.Repeat("b", 64))
	signature, err = bundlesig.Sign(private, manifest, chainCommit, 12, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return dir, public, private, manifest, signature
}

func TestMacInstallChainAcceptsASignedManifest(t *testing.T) {
	dir, public, _, manifest, signature := chainFixture(t)
	writeDescribe(t, filepath.Join(dir, "describe.json"), bundlesig.SSHPublicKeyLine(public, "rn-release-key"), manifest, signature)

	out, err := runChain(t, dir, "describe.json", bundlesig.PublicKeySHA256(public))
	if err != nil {
		t.Fatalf("a correctly signed manifest was rejected: %v\n%s", err, out)
	}
	// 提交与序号必须来自**验过签的那串字节**，归档摘要必须来自已验签的清单
	want := fmt.Sprintf("RESULT %s 12 %s", chainCommit, strings.Repeat("b", 64))
	if !strings.Contains(out, want) {
		t.Fatalf("the chain did not hand back the signed values (%s):\n%s", want, out)
	}
}

// 攻破服务端的人手里没有那把私钥。他能做的是拿自己的密钥重签一份处处自洽的清单——那正是
// 带外那一个指纹要挡的东西，而且要在**认公钥**那一步就挡住，不是在验签那一步。
func TestMacInstallChainRejectsAManifestSignedByAnotherKey(t *testing.T) {
	dir, public, _, manifest, _ := chainFixture(t)
	_, attacker, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := bundlesig.Sign(attacker, manifest, chainCommit, 99, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	attackerPub, _ := attacker.Public().(ed25519.PublicKey)
	writeDescribe(t, filepath.Join(dir, "describe.json"), bundlesig.SSHPublicKeyLine(attackerPub, "rn-release-key"), manifest, forged)

	out, err := runChain(t, dir, "describe.json", bundlesig.PublicKeySHA256(public))
	if err == nil {
		t.Fatalf("a manifest signed by another key was accepted:\n%s", out)
	}
	if !strings.Contains(out, "发布公钥指纹") {
		t.Fatalf("the refusal should name the fingerprint that did not match:\n%s", out)
	}
}

// 真公钥配真签名，但清单被改过：签名覆盖的是清单的摘要，改一个字节就对不上。
func TestMacInstallChainRejectsATamperedManifest(t *testing.T) {
	dir, public, _, _, signature := chainFixture(t)
	tampered := chainManifest(strings.Repeat("e", 64))
	writeDescribe(t, filepath.Join(dir, "describe.json"), bundlesig.SSHPublicKeyLine(public, "rn-release-key"), tampered, signature)

	out, err := runChain(t, dir, "describe.json", bundlesig.PublicKeySHA256(public))
	if err == nil {
		t.Fatalf("a tampered manifest was accepted:\n%s", out)
	}
	if !strings.Contains(out, "签名覆盖的是") {
		t.Fatalf("the refusal should name the manifest digest mismatch:\n%s", out)
	}
}

// 人把指纹抄错一位。这是最常见的一种失败，报错必须指向"去密码管理器再核一遍"。
func TestMacInstallChainRejectsAMistypedFingerprint(t *testing.T) {
	dir, public, _, manifest, signature := chainFixture(t)
	writeDescribe(t, filepath.Join(dir, "describe.json"), bundlesig.SSHPublicKeyLine(public, "rn-release-key"), manifest, signature)

	mistyped := []byte(bundlesig.PublicKeySHA256(public))
	if mistyped[0] == '0' {
		mistyped[0] = '1'
	} else {
		mistyped[0] = '0'
	}
	out, err := runChain(t, dir, "describe.json", string(mistyped))
	if err == nil {
		t.Fatalf("a mistyped fingerprint was accepted:\n%s", out)
	}
	if !strings.Contains(out, "密码管理器") {
		t.Fatalf("the refusal should send the operator back to the password manager:\n%s", out)
	}
}

// 安装包还没签：不能装，而且要说清楚下一步去哪儿签。
func TestMacInstallChainRejectsAnUnsignedBundle(t *testing.T) {
	dir, public, _, _, _ := chainFixture(t)
	writeDescribe(t, filepath.Join(dir, "describe.json"), bundlesig.SSHPublicKeyLine(public, "rn-release-key"), nil, nil)

	out, err := runChain(t, dir, "describe.json", bundlesig.PublicKeySHA256(public))
	if err == nil {
		t.Fatalf("an unsigned bundle was accepted:\n%s", out)
	}
	if !strings.Contains(out, "bundle-sign") {
		t.Fatalf("the refusal should say where the signature comes from:\n%s", out)
	}
}
