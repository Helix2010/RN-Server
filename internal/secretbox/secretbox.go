package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const keySize = 32

type Box struct {
	aead cipher.AEAD
}

func New(encodedKey string) (*Box, error) {
	if encodedKey == "" {
		return nil, errors.New("STORAGE_MASTER_KEY is not configured")
	}
	key, err := base64.RawStdEncoding.DecodeString(encodedKey)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(encodedKey)
	}
	if err != nil || len(key) != keySize {
		return nil, errors.New("STORAGE_MASTER_KEY must be a base64-encoded 32-byte key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create storage cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create storage AEAD: %w", err)
	}
	return &Box{aead: aead}, nil
}

func (b *Box) Encrypt(plaintext, associatedData string) ([]byte, error) {
	if plaintext == "" {
		return nil, nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("create secret nonce: %w", err)
	}
	return b.aead.Seal(nonce, nonce, []byte(plaintext), []byte(associatedData)), nil
}

func (b *Box) Decrypt(ciphertext []byte, associatedData string) (string, error) {
	if len(ciphertext) == 0 {
		return "", nil
	}
	nonceSize := b.aead.NonceSize()
	if len(ciphertext) <= nonceSize {
		return "", errors.New("encrypted storage secret is invalid")
	}
	nonce, payload := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := b.aead.Open(nil, nonce, payload, []byte(associatedData))
	if err != nil {
		return "", errors.New("encrypted storage secret cannot be decrypted")
	}
	return string(plaintext), nil
}
