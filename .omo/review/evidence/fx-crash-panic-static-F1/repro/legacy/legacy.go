// Package legacy prepares a DES block cipher in init().
package legacy

import (
	"crypto/cipher"
	"crypto/des"
	"os"
)

var Block cipher.Block

func init() {
	if os.Getenv("REPRO") == "des" {
		Block, _ = des.NewCipher([]byte("8bytekey"))
	}
}
