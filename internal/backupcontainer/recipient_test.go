package backupcontainer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

func encodeRecipient(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return base64.StdEncoding.EncodeToString(block)
}

// 配对规则是打包机和服务端各自推导的，两边推出来的必须逐字一致。
// 硬编码成三个常量就没有这条保障了
func TestPairsAreTheThreeCombinations(t *testing.T) {
	pairs := Pairs()
	if len(pairs) != 3 {
		t.Fatalf("2-of-3 has 3 pairs, got %d", len(pairs))
	}
	want := []Pair{
		{Name: "AB", Inner: "A", Outer: "B"},
		{Name: "AC", Inner: "A", Outer: "C"},
		{Name: "BC", Inner: "B", Outer: "C"},
	}
	for i, p := range pairs {
		if p != want[i] {
			t.Fatalf("pair %d: got %+v, want %+v", i, p, want[i])
		}
	}
}

// 每一组的两个收件人必须不同——相同就是「一个人能单独开」，门限当场失效
func TestEveryPairNeedsTwoDifferentPeople(t *testing.T) {
	for _, p := range Pairs() {
		if p.Inner == p.Outer {
			t.Fatalf("pair %s seals both layers to %s: one person could open it alone", p.Name, p.Inner)
		}
	}
}

// 每个人都必须至少出现在两组里，否则「失去任意一个人仍然能开」不成立
func TestLosingAnyOnePersonStillLeavesAnOpenablePair(t *testing.T) {
	for _, lost := range SlotNames {
		usable := 0
		for _, p := range Pairs() {
			if p.Inner != lost && p.Outer != lost {
				usable++
			}
		}
		if usable == 0 {
			t.Fatalf("losing %s leaves no openable package: this is not 2-of-3", lost)
		}
	}
}

// 内层只做两份不是三份：AB 与 AC 共用封给 A 的那一份，而那一份是打包机
// 解密全部租户签名密钥 + 打 tar 的重活
func TestInnerSlotsAreDeduplicated(t *testing.T) {
	got := InnerSlots()
	if len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Fatalf("expected the inner payload to be sealed twice (A, B), got %v", got)
	}
}

func TestParsePublicKeyRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, minRecipientBits)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePublicKey(encodeRecipient(t, &key.PublicKey))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.N.Cmp(key.PublicKey.N) != 0 || parsed.E != key.PublicKey.E {
		t.Fatal("parsed key is not the one we encoded")
	}
	// 前后的空白要能容忍：env 文件里换行和空格几乎一定会混进来
	if _, err := ParsePublicKey("  \n" + encodeRecipient(t, &key.PublicKey) + "\n "); err != nil {
		t.Fatalf("surrounding whitespace should be tolerated: %v", err)
	}
}

func TestParsePublicKeyRejections(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKIXPublicKey(&small.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemOnly := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw})

	cases := []struct{ name, value, want string }{
		{"empty", "", "empty"},
		{"not base64", "-----BEGIN PUBLIC KEY-----", "not valid base64"},
		{"base64 of something else", base64.StdEncoding.EncodeToString([]byte("hello")), "not PEM"},
		// 最容易犯的错：把 PEM 原样贴进 env 而不是 base64 一层。报错必须说清楚
		{"raw PEM not base64ed", string(pemOnly), "not valid base64"},
		{"too small", base64.StdEncoding.EncodeToString(pemOnly), "2048 bits"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePublicKey(tc.value)
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}
