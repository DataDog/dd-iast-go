// Package fp is an ordinary application package: it compiles a validation
// regexp and computes a build fingerprint with SHA-1 while initializing.
package fp

import (
	"crypto/sha1"
	"encoding/hex"
	"regexp"
)

var idPattern = regexp.MustCompile(`^[a-f0-9]{40}$`)

var fingerprint string

func init() {
	h := sha1.New() // weak-crypto hook fires during package init
	h.Write([]byte("build-tag"))
	fingerprint = hex.EncodeToString(h.Sum(nil))
}

// Fingerprint returns the init-time digest.
func Fingerprint() string { return fingerprint }

// Valid reports whether s looks like a sha1 hex digest.
func Valid(s string) bool { return idPattern.MatchString(s) }
