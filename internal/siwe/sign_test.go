package siwe

import (
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestSignPersonalRoundTrips(t *testing.T) {
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	body := []byte(`{"schemaVersion":1,"issuedAt":1789178790393}`)

	signature, err := SignPersonal(key, body)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// RecoverAddress is the verifier the client mirrors; if the byte order were
	// wrong this is where it shows, not in production.
	recovered, err := RecoverAddress(string(body), signature)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if !strings.EqualFold(recovered, AddressOf(key)) {
		t.Fatalf("recovered %s, want %s", recovered, AddressOf(key))
	}
}

func TestSignPersonalRejectsATamperedBody(t *testing.T) {
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signature, err := SignPersonal(key, []byte("original"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	recovered, err := RecoverAddress("0riginal", signature)
	if err != nil {
		// recovering a different address is the usual outcome; an error is fine too
		return
	}
	if strings.EqualFold(recovered, AddressOf(key)) {
		t.Fatal("a tampered body recovered the signer address")
	}
}

func TestPersonalHashCountsBytesNotRunes(t *testing.T) {
	// 一个多字节字符：按 rune 数会得到不同的前缀，两端就再也对不上
	message := "价格"
	if got, want := len([]byte(message)), 6; got != want {
		t.Fatalf("fixture is wrong: %d bytes", got)
	}
	if string(PersonalHashBytes([]byte(message))) != string(personalHash(message)) {
		t.Fatal("byte and string envelopes disagree")
	}
}
