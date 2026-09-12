package siwe

import (
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// PersonalHashBytes applies the EIP-191 personal_sign envelope to arbitrary
// bytes. The length prefix counts BYTES, which is why this takes a []byte and
// not a string: a response body is not necessarily valid UTF-8, and measuring
// it as runes would produce a different digest on both sides.
func PersonalHashBytes(message []byte) []byte {
	return Keccak256([]byte(fmt.Sprintf("%s%d", personalSignPrefix, len(message))), message)
}

// SignPersonal signs message with the EIP-191 envelope and returns the 65-byte
// r || s || v signature that ethers' verifyMessage expects, with v in 27/28.
//
// dcrd's compact encoding puts the recovery id FIRST and adds 27 to it, which
// is the opposite of what every Ethereum tool wants. RecoverAddress documents
// the same reordering in the other direction; keep the two in sync.
func SignPersonal(key *secp256k1.PrivateKey, message []byte) ([]byte, error) {
	if key == nil {
		return nil, errors.New("siwe: signing key is nil")
	}
	compact := ecdsa.SignCompact(key, PersonalHashBytes(message), false)
	if len(compact) != 65 {
		return nil, errors.New("siwe: unexpected compact signature length")
	}
	signature := make([]byte, 65)
	copy(signature, compact[1:])
	// compact[0] is recovery id + 27 for an uncompressed key, which is already
	// the 27/28 that ethers wants.
	signature[64] = compact[0]
	return signature, nil
}

// AddressOf returns the EIP-55 address a private key signs as. Callers pin this
// on the client, so it must be derived exactly like RecoverAddress derives it.
func AddressOf(key *secp256k1.PrivateKey) string {
	return addressFromPublicKey(key.PubKey())
}
