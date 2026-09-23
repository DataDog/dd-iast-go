// Package hasher is an ordinary application package: it compiles a regular
// expression and computes a digest while initializing.
package hasher

import (
	"crypto/md5"
	"regexp"
)

var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// Seed is computed at package initialization.
var Seed = md5.Sum([]byte("seed"))

// Valid reports whether id looks like an md5 hex digest.
func Valid(id string) bool { return idPattern.MatchString(id) }
