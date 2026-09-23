package bconv

import "strings"

var _ = strings.ToUpper

// Key turns a raw key into a map key.
func Key(b []byte) string { return string(b) }
