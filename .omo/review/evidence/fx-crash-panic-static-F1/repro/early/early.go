// Package early sorts before github.com/DataDog/... in init order.
package early

import (
	"crypto/md5"
	"os"
)

var Sum [16]byte

func init() {
	if os.Getenv("REPRO") == "early" {
		Sum = md5.Sum([]byte("early"))
	}
}
