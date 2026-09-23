// Package legacy2 prepares a DES cipher and hex-encodes a probe block at init.
package legacy2

import (
	"crypto/des"
	"encoding/hex"
	"os"
)

var Probe = compute()

func compute() string {
	if os.Getenv("REPRO") != "des2" {
		return "skipped"
	}
	b, _ := des.NewCipher([]byte("8bytekey"))
	dst := make([]byte, 8)
	b.Encrypt(dst, []byte("12345678"))
	return hex.EncodeToString(dst)[:8]
}
