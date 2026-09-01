package siwe

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// 由 ethers v6 用 BIP-39 官方全零熵助记词
// (abandon…about, m/44'/60'/0'/0/0) 实际签出的向量。
const (
	testAddress = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
	testMessage = "api.anyfun.win wants you to sign in with your Ethereum account:\n" +
		"0x9858EfFD232B4033E47d90003D41EC34EcaEda94\n\n" +
		"Sign in to continue.\n\n" +
		"URI: https://api.anyfun.win\nVersion: 1\nChain ID: 56\n" +
		"Nonce: abc123nonce\nIssued At: 2026-09-01T00:00:00.000Z\n" +
		"Expiration Time: 2026-09-08T00:00:00.000Z"
	testSignature = "decd75094e15cda9b82ce5f4b7af8a5cfcb25630bd1735163ee82b98a77a011059b09a185a52d43b05abe64e019698efcfb4e4b42ecdc4a80194a3d2b2cf35821b"
	// 多字节消息：EIP-191 的长度前缀必须按字节而不是按字符计算
	unicodeMessage   = "héllo 世界"
	unicodeSignature = "b98163e6bde575a773cb0cb0e6d5664871240514a2fbbfbb4ee2959677a7471556b261ac10ead04c6bd78778c85551b3c2aa616481a9bdffdfed3d876d3671c11b"
)

func mustDecode(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return raw
}

func signedAt() time.Time {
	return time.Date(2026, 9, 1, 0, 5, 0, 0, time.UTC)
}

func TestRecoverAddressMatchesAnEthersSignature(t *testing.T) {
	got, err := RecoverAddress(testMessage, mustDecode(t, testSignature))
	if err != nil || got != testAddress {
		t.Fatalf("recover = %q, %v; want %q", got, err, testAddress)
	}
}

func TestRecoverAddressCountsMessageBytesNotRunes(t *testing.T) {
	got, err := RecoverAddress(unicodeMessage, mustDecode(t, unicodeSignature))
	if err != nil || got != testAddress {
		t.Fatalf("recover = %q, %v; want %q", got, err, testAddress)
	}
}

func TestRecoverAddressAcceptsLegacyRecoveryIDs(t *testing.T) {
	signature := mustDecode(t, testSignature)
	signature[64] -= 27 // v = 0/1 而不是 27/28
	got, err := RecoverAddress(testMessage, signature)
	if err != nil || got != testAddress {
		t.Fatalf("recover = %q, %v; want %q", got, err, testAddress)
	}
}

func TestRecoverAddressRejectsTamperedInput(t *testing.T) {
	if _, err := RecoverAddress(testMessage, []byte{1, 2, 3}); err == nil {
		t.Fatal("a short signature must be rejected")
	}
	signature := mustDecode(t, testSignature)
	signature[5] ^= 0xff
	got, err := RecoverAddress(testMessage, signature)
	if err == nil && got == testAddress {
		t.Fatal("a tampered signature must not recover the original address")
	}
	// 改一个字符的消息不得恢复出同一地址
	other, err := RecoverAddress(testMessage+" ", mustDecode(t, testSignature))
	if err == nil && other == testAddress {
		t.Fatal("a modified message must not recover the original address")
	}
}

func TestChecksumAddressFollowsEIP55(t *testing.T) {
	// EIP-55 规范里的向量
	cases := []string{
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
	}
	for _, want := range cases {
		if got := ChecksumAddress(strings.ToLower(want)); got != want {
			t.Fatalf("ChecksumAddress = %q; want %q", got, want)
		}
	}
}

func TestParseReadsTheBoundFields(t *testing.T) {
	parsed, err := Parse(testMessage)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Domain != "api.anyfun.win" || parsed.Address != testAddress {
		t.Fatalf("domain/address = %q/%q", parsed.Domain, parsed.Address)
	}
	if parsed.Nonce != "abc123nonce" || parsed.ChainID != "56" {
		t.Fatalf("nonce/chain = %q/%q", parsed.Nonce, parsed.ChainID)
	}
	if parsed.IssuedAt.IsZero() || parsed.Expiration.IsZero() {
		t.Fatal("issuedAt/expiration were not parsed")
	}
}

func TestParseRejectsMalformedMessages(t *testing.T) {
	for name, message := range map[string]string{
		"empty":      "",
		"no header":  "please sign this\n0xabc",
		"no address": "api.anyfun.win wants you to sign in with your Ethereum account:\n\nNonce: x",
		"no nonce":   "api.anyfun.win wants you to sign in with your Ethereum account:\n" + testAddress + "\n\nURI: https://api.anyfun.win",
	} {
		if _, err := Parse(message); err == nil {
			t.Fatalf("%s: expected a parse error", name)
		}
	}
}

func baseRequest(t *testing.T) VerifyRequest {
	t.Helper()
	return VerifyRequest{
		Message:   testMessage,
		Signature: mustDecode(t, testSignature),
		Domain:    "api.anyfun.win",
		Nonce:     "abc123nonce",
		Now:       signedAt(),
		MaxAge:    10 * time.Minute,
	}
}

func TestVerifyAcceptsAMatchingChallenge(t *testing.T) {
	address, err := Verify(baseRequest(t))
	if err != nil || address != testAddress {
		t.Fatalf("verify = %q, %v", address, err)
	}
}

func TestVerifyBindsDomainNonceAndTime(t *testing.T) {
	wrongDomain := baseRequest(t)
	wrongDomain.Domain = "evil.example"
	if _, err := Verify(wrongDomain); err != ErrDomainMismatch {
		t.Fatalf("domain: got %v", err)
	}

	wrongNonce := baseRequest(t)
	wrongNonce.Nonce = "someone-elses-nonce"
	if _, err := Verify(wrongNonce); err != ErrNonceMismatch {
		t.Fatalf("nonce: got %v", err)
	}

	tooLate := baseRequest(t)
	tooLate.Now = signedAt().Add(time.Hour)
	if _, err := Verify(tooLate); err != ErrExpired {
		t.Fatalf("max age: got %v", err)
	}

	afterExpiry := baseRequest(t)
	afterExpiry.Now = time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	afterExpiry.MaxAge = 0
	if _, err := Verify(afterExpiry); err != ErrExpired {
		t.Fatalf("expiration: got %v", err)
	}
}

func TestVerifyRejectsAnAddressSwap(t *testing.T) {
	// 消息里声明的是别人的地址，但签名是我们的 —— 必须拒绝
	swapped := baseRequest(t)
	swapped.Message = strings.Replace(
		testMessage, testAddress,
		"0x0000000000000000000000000000000000000001", 1,
	)
	if _, err := Verify(swapped); err != ErrAddressMismatch {
		t.Fatalf("address swap: got %v", err)
	}
}

func TestVerifyIsCaseInsensitiveAboutTheDomain(t *testing.T) {
	upper := baseRequest(t)
	upper.Domain = "API.AnyFun.WIN"
	if _, err := Verify(upper); err != nil {
		t.Fatalf("domain case: %v", err)
	}
}
