package buildkeystore

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSealToOnlyOpensWithThatMachinesKey(t *testing.T) {
	priv, recipient, err := NewAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealTo(sample(), recipient)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenWith(sealed, priv)
	if err != nil {
		t.Fatalf("对的私钥打不开：%v", err)
	}
	if got != sample() {
		t.Fatalf("解出来的内容不一致：%+v", got)
	}

	// 另一台打包机的私钥必须打不开——这正是"服务端加密给谁"这件事的全部意义
	otherPriv, _, err := NewAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWith(sealed, otherPriv); err == nil {
		t.Fatal("换一把私钥竟然也能打开")
	}
}

// 服务端只有公钥。它存下去的盒子，它自己打不开——原来那条安全论证靠的就是这一点，
// 换成公钥之后必须仍然成立。
func TestServerSideCannotOpenWhatItSealed(t *testing.T) {
	_, recipient, err := NewAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealTo(sample(), recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWith(sealed, nil); err == nil {
		t.Fatal("没有私钥也能解开")
	}
	// 公钥本身不能用来解
	raw, _ := base64.StdEncoding.DecodeString(recipient.PublicKey)
	if _, err := OpenWith(sealed, raw); err == nil {
		t.Fatal("拿公钥当私钥竟然解开了")
	}
}

// 密文里的临时公钥被换掉就解不开：它同时是 KDF 的输入和 AEAD 的 AAD
func TestTamperingWithTheEphemeralKeyIsDetected(t *testing.T) {
	priv, recipient, _ := NewAgentKey()
	sealed, _ := SealTo(sample(), recipient)
	_, other, _ := NewAgentKey()
	sealed.EphemeralPublicKey = other.PublicKey
	if _, err := OpenWith(sealed, priv); err == nil {
		t.Fatal("换掉临时公钥仍然解开了")
	}
}

// 指纹是给人核对用的：同一把公钥永远同一个值，不同公钥不能撞
func TestFingerprintIdentifiesTheMachine(t *testing.T) {
	_, a, _ := NewAgentKey()
	_, b, _ := NewAgentKey()
	if a.Fingerprint() == "" || len(a.Fingerprint()) != 16 {
		t.Fatalf("指纹形状不对：%q", a.Fingerprint())
	}
	if a.Fingerprint() != a.Fingerprint() {
		t.Fatal("同一把公钥算出两个指纹")
	}
	if a.Fingerprint() == b.Fingerprint() {
		t.Fatal("两把公钥撞了指纹")
	}
	if (Recipient{PublicKey: "不是 base64"}).Fingerprint() != "" {
		t.Fatal("坏公钥应当没有指纹")
	}
}

// v1 的盒子还在库里（anyfun 那把就是），必须继续能开
func TestV1BoxesStillOpenWithTheirPassphrase(t *testing.T) {
	sealed, err := Seal(sample(), "passphrase-long-enough")
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Version != formatV1 {
		t.Fatalf("Seal 应当还是产出 v1：%d", sealed.Version)
	}
	got, err := Open(sealed, "passphrase-long-enough")
	if err != nil || got != sample() {
		t.Fatalf("v1 打不开了：%v", err)
	}
	// 而 v2 的解法不该认它
	if _, err := OpenWith(sealed, []byte("x")); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("v2 不该认 v1 的盒子：%v", err)
	}
}
