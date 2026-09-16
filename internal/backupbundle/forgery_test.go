package backupbundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/Helix2010/RN-Server/internal/backupcontainer"
)

// 这条测试对应的是**唯一一条会导致恢复时执行攻击者代码的路径**（设计 §4.3、§9）。
//
// 容器只有保密性，没有真实性：RSA-OAEP 用的是公钥，而公钥不是秘密——指纹就印在
// 控制台上，任何看得到配置的人都有。所以拿到桶写权限的人可以从零封一个包：
// 两层 MAC 都通过、两把私钥都解得开、里面是他写的 recover.sh。而那个脚本恢复时
// 必然以 root 跑，在平台最脆弱的那一天、由两位持有人亲手执行。
//
// 这里真的扮演一次那个攻击者：**只用三把公钥**，不碰任何私钥、不碰打包机的
// 签名密钥，造一个完整合法的包。然后确认两个锚点都抓得住它。
func TestAForgedPackageOpensCleanlyButFailsBothAnchors(t *testing.T) {
	holders := testHolders(t)
	real, realSigningPub := testInputWithSigner(t, holders)
	realSink := newSink()
	realPackages, err := Assemble(real, realSink)
	if err != nil {
		t.Fatalf("assemble the genuine packages: %v", err)
	}

	// ---- 攻击者登场。他手上只有三把**公钥**（从配置或控制台抄来的） ----
	attacker := forgeInput(t, real)
	forgedSink := newSink()
	forgedPackages, err := Assemble(attacker, forgedSink)
	if err != nil {
		t.Fatalf("伪造失败了？那说明容器格式挡住了公钥持有者，和设计的判断不一致: %v", err)
	}

	pair := backupcontainer.Pairs()[0]
	byslot := map[string]*rsa.PrivateKey{}
	for _, h := range holders {
		byslot[h.slot] = h.key
	}

	// ---- 第一件事：确认伪造**确实成功**了 ----
	// 这不是"测试通过就好"，而是设计诚实性的验证：文档说「MAC 通过只说明没损坏、
	// 没被拼接，不说明没被替换」。如果这里开不了，说明文档把容器说弱了
	outer := openOuter(t, forgedSink.packages[pair.Name].Bytes(), byslot[pair.Outer])
	if _, _, err := backupcontainer.Open(bytes.NewReader(outer[nameInner]), byslot[pair.Inner]); err != nil {
		t.Fatalf("伪造包的内层打不开: %v", err)
	}
	// 攻击者控制 innerFiles 的目标路径，而 recover.sh 是照它渲染的——
	// 这就是他把自己的内容放进那个以 root 跑的脚本的办法
	if !bytes.Contains(outer[nameRecoverSh], []byte("/tmp/anywhere")) {
		t.Fatal("伪造包的 recover.sh 应当照攻击者的清单渲染")
	}
	t.Log("确认：只用公钥就能造出一个两层都解得开、MAC 全通过的包——" +
		"这正是设计 §4.3 说的那件事，所以真实性只能靠容器外面那两个锚点")

	// ---- 锚点一：对象的 sha256 和库里那一行对不上 ----
	genuine := map[string]string{}
	for _, pkg := range realPackages {
		genuine[pkg.Pair] = pkg.SHA256
	}
	for _, pkg := range forgedPackages {
		if genuine[pkg.Pair] == pkg.SHA256 {
			t.Fatalf("%s: 伪造包的 sha256 和真包一样，第一个锚点失效", pkg.Pair)
		}
	}

	// ---- 锚点二：打包机的签名验不过 ----
	// 攻击者用自己的 Ed25519 密钥签，因为他没有打包机那把
	if err := backupcontainer.VerifyPayload(realSigningPub, outer[nameInner], outer[nameInnerSig]); err == nil {
		t.Fatal("伪造包的内层签名竟然通过了登记在案的公钥验证——第二个锚点失效")
	}

	// 反过来：真包必须验得过，否则这条断言只是在证明「随便什么都验不过」
	realOuter := openOuter(t, realSink.packages[pair.Name].Bytes(), byslot[pair.Outer])
	if err := backupcontainer.VerifyPayload(realSigningPub, realOuter[nameInner], realOuter[nameInnerSig]); err != nil {
		t.Fatalf("真包的签名反而验不过: %v", err)
	}
}

// forgeInput 造一份攻击者的输入：**只用真输入里的公钥**，其余全是他自己的。
func forgeInput(t *testing.T, real Input) Input {
	t.Helper()
	// 攻击者自己的签名密钥——他没有打包机那把
	_, attackerSigner, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	poison, err := tarFiles(map[string][]byte{
		"agent-key": []byte("whatever, nobody checks this until it is too late"),
	})
	if err != nil {
		t.Fatal(err)
	}

	inner := map[string]InnerPart{}
	for _, slot := range backupcontainer.InnerSlots() {
		var recipient *rsa.PublicKey
		for _, r := range real.Recipients {
			if r.Slot == slot {
				recipient = r.Key // 公钥而已，不是秘密
			}
		}
		var sealed bytes.Buffer
		meta := backupcontainer.Meta{Layer: backupcontainer.LayerInner, Seq: real.Seq, InstanceID: real.InstanceID}
		if err := backupcontainer.Seal(&sealed, recipient, meta, bytes.NewReader(poison), int64(len(poison))); err != nil {
			t.Fatal(err)
		}
		inner[slot] = InnerPart{
			Slot: slot, Sealed: sealed.Bytes(),
			Signature: backupcontainer.SignPayload(attackerSigner, sealed.Bytes()),
		}
	}

	forged := real
	forged.AgentInner = inner
	forged.CreatedAt = real.CreatedAt.Add(time.Minute)
	// 攻击者会把清单抄得一模一样，好让人工核对也看不出来
	forged.ServerFiles = map[string][]byte{
		"rn-foundation.env": []byte("STORAGE_MASTER_KEY=not-the-real-one\n"),
	}
	forged.AgentManifest = []FileEntry{{
		Path: "agent-key", Size: 1, SHA256: "00", Target: "/tmp/anywhere",
		Mode: "0600", Owner: "builder:builder",
	}}
	return forged
}
