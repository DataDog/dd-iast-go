// Package digest computes a build fingerprint in a package-level var (no regexp import).
package digest

import (
	"crypto/sha1"
	"encoding/hex"
	"os"
)

var Fingerprint = compute()

func compute() string {
	if os.Getenv("REPRO") != "sha1" {
		return "skipped"
	}
	h := sha1.New()
	h.Write([]byte("build-42"))
	return hex.EncodeToString(h.Sum(nil))[:8]
}
