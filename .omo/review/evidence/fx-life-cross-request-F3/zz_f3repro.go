// Independent reproducer for phase-3 verification of life-cross-request-F3.
// Not part of the product. This file lives in the woven root package so each
// call below is an ordinary supported direct call site.

package testapp

import "bytes"

// F3WriteTainted wraps a pooled slice with bytes.NewBuffer, writes the value
// with a direct woven WriteString, and returns the direct woven String result.
func F3WriteTainted(backing []byte, value string) string {
	buf := bytes.NewBuffer(backing[:0])
	buf.WriteString(value) // woven bytes.Buffer.WriteString
	return buf.String()    // woven bytes.Buffer.String
}

// F3NewBufferString wraps a recycled slice with a *new* bytes.Buffer and
// returns the direct woven String result.
func F3NewBufferString(backing []byte) string {
	buf := bytes.NewBuffer(backing) // no hook on NewBuffer
	return buf.String()            // woven bytes.Buffer.String
}
