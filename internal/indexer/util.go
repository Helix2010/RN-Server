package indexer

import (
	"crypto/rand"
	"encoding/hex"
)

func randomID(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "0"
	}
	return hex.EncodeToString(buf)[:n]
}
