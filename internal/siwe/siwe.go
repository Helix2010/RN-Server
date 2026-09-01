// Package siwe verifies Sign-In with Ethereum (EIP-4361) messages.
//
// The server never holds a private key: it only recovers the signer's address
// from an EIP-191 personal_sign signature and checks that the message body
// matches the challenge it issued (domain, address, nonce, validity window).
package siwe

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

const personalSignPrefix = "\x19Ethereum Signed Message:\n"

// Message is the subset of EIP-4361 fields this server cares about.
type Message struct {
	Domain     string
	Address    string
	URI        string
	Version    string
	ChainID    string
	Nonce      string
	IssuedAt   time.Time
	Expiration time.Time
}

var (
	ErrMalformed       = errors.New("siwe: message is malformed")
	ErrBadSignature    = errors.New("siwe: signature does not recover an address")
	ErrAddressMismatch = errors.New("siwe: signature was not produced by the stated address")
	ErrDomainMismatch  = errors.New("siwe: message domain does not match this tenant")
	ErrNonceMismatch   = errors.New("siwe: message nonce does not match the challenge")
	ErrExpired         = errors.New("siwe: message is expired or not yet valid")
)

// Keccak256 is Ethereum's hash (the pre-standard Keccak, not SHA3-256).
func Keccak256(data ...[]byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	for _, part := range data {
		_, _ = hash.Write(part)
	}
	return hash.Sum(nil)
}

// personalHash applies the EIP-191 personal_sign envelope. The length prefix
// counts BYTES, not runes, so multi-byte messages must not be measured with
// len([]rune(...)).
func personalHash(message string) []byte {
	raw := []byte(message)
	return Keccak256([]byte(fmt.Sprintf("%s%d", personalSignPrefix, len(raw))), raw)
}

// RecoverAddress returns the EIP-55 checksummed address that signed message.
// signature must be 65 bytes: r || s || v, where v is 27/28 (or 0/1).
func RecoverAddress(message string, signature []byte) (string, error) {
	if len(signature) != 65 {
		return "", ErrBadSignature
	}
	v := signature[64]
	if v >= 27 {
		v -= 27
	}
	if v > 3 {
		return "", ErrBadSignature
	}
	// dcrd wants the recovery id first, and adds 27 for "compact" encoding.
	compact := make([]byte, 65)
	compact[0] = v + 27
	copy(compact[1:], signature[:64])
	publicKey, _, err := ecdsa.RecoverCompact(compact, personalHash(message))
	if err != nil {
		return "", ErrBadSignature
	}
	return addressFromPublicKey(publicKey), nil
}

func addressFromPublicKey(key *secp256k1.PublicKey) string {
	// Ethereum hashes the 64-byte uncompressed key without the 0x04 prefix.
	uncompressed := key.SerializeUncompressed()
	digest := Keccak256(uncompressed[1:])
	return ChecksumAddress(fmt.Sprintf("%x", digest[12:]))
}

// ChecksumAddress applies EIP-55 mixed-case checksumming.
func ChecksumAddress(address string) string {
	lower := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(address, "0x"), "0X"))
	digest := Keccak256([]byte(lower))
	out := []byte("0x" + lower)
	for index := 0; index < len(lower); index++ {
		char := lower[index]
		if char < 'a' || char > 'f' {
			continue
		}
		nibble := digest[index/2]
		if index%2 == 0 {
			nibble >>= 4
		} else {
			nibble &= 0x0f
		}
		if nibble >= 8 {
			out[2+index] = char - 32
		}
	}
	return string(out)
}

func SameAddress(left, right string) bool {
	return strings.EqualFold(strings.TrimPrefix(left, "0x"), strings.TrimPrefix(right, "0x"))
}

// Parse reads the EIP-4361 fields this server validates. It is deliberately
// strict about the first two lines, which bind the domain and the address.
func Parse(message string) (Message, error) {
	lines := strings.Split(strings.ReplaceAll(message, "\r\n", "\n"), "\n")
	if len(lines) < 2 {
		return Message{}, ErrMalformed
	}
	const wantsSuffix = " wants you to sign in with your Ethereum account:"
	if !strings.HasSuffix(lines[0], wantsSuffix) {
		return Message{}, ErrMalformed
	}
	parsed := Message{
		Domain:  strings.TrimSuffix(lines[0], wantsSuffix),
		Address: strings.TrimSpace(lines[1]),
	}
	if parsed.Domain == "" || parsed.Address == "" {
		return Message{}, ErrMalformed
	}
	for _, line := range lines[2:] {
		key, value, found := strings.Cut(line, ": ")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "URI":
			parsed.URI = strings.TrimSpace(value)
		case "Version":
			parsed.Version = strings.TrimSpace(value)
		case "Chain ID":
			parsed.ChainID = strings.TrimSpace(value)
		case "Nonce":
			parsed.Nonce = strings.TrimSpace(value)
		case "Issued At":
			if at, err := time.Parse(time.RFC3339, strings.TrimSpace(value)); err == nil {
				parsed.IssuedAt = at
			}
		case "Expiration Time":
			if at, err := time.Parse(time.RFC3339, strings.TrimSpace(value)); err == nil {
				parsed.Expiration = at
			}
		}
	}
	if parsed.Nonce == "" {
		return Message{}, ErrMalformed
	}
	return parsed, nil
}

// VerifyRequest is everything the server knows independently of the client.
type VerifyRequest struct {
	Message   string
	Signature []byte
	// Domain the request actually arrived on (tenant domain).
	Domain string
	// Nonce the server issued and is about to consume.
	Nonce string
	Now   time.Time
	// MaxAge bounds how long a challenge stays signable even if the client
	// asked for a longer expiration.
	MaxAge time.Duration
}

// Verify recovers the signer and checks the message against the server's own
// view. It returns the checksummed address on success.
func Verify(request VerifyRequest) (string, error) {
	parsed, err := Parse(request.Message)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(parsed.Domain, request.Domain) {
		return "", ErrDomainMismatch
	}
	if parsed.Nonce != request.Nonce {
		return "", ErrNonceMismatch
	}
	if !parsed.IssuedAt.IsZero() {
		if request.Now.Before(parsed.IssuedAt.Add(-2 * time.Minute)) {
			return "", ErrExpired
		}
		if request.MaxAge > 0 && request.Now.After(parsed.IssuedAt.Add(request.MaxAge)) {
			return "", ErrExpired
		}
	}
	if !parsed.Expiration.IsZero() && request.Now.After(parsed.Expiration) {
		return "", ErrExpired
	}
	recovered, err := RecoverAddress(request.Message, request.Signature)
	if err != nil {
		return "", err
	}
	if !SameAddress(recovered, parsed.Address) {
		return "", ErrAddressMismatch
	}
	return recovered, nil
}
