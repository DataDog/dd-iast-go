// Review reproducer helpers for node life-cross-request. Not part of the product.
// These live in the woven root package (the external test package is not
// woven), so every call below is an ordinary, supported, direct call site.

package testapp

import (
	"bytes"
	"io"
	"strings"
)

// ReviewReadBody reads a request body with io.ReadAll (owned-result adoption).
func ReviewReadBody(r io.Reader) []byte {
	body, _ := io.ReadAll(r)
	return body
}

// ReviewQueryFromPooled refills a recycled slice with clean text and converts
// it with a supported declaration-context conversion.
func ReviewQueryFromPooled(buf []byte, clean string) string {
	buf = append(buf[:0], clean...)
	query := string(buf)
	return query
}

// ReviewBuilderWrite writes value with a direct woven WriteString and returns
// the direct woven String() result.
func ReviewBuilderWrite(sb *strings.Builder, value string) string {
	sb.WriteString(value)
	out := sb.String()
	return out
}

// ReviewBuilderString is a direct woven strings.Builder.String call.
func ReviewBuilderString(sb *strings.Builder) string {
	out := sb.String()
	return out
}

// ReviewBuilderReset is a direct woven strings.Builder.Reset call.
func ReviewBuilderReset(sb *strings.Builder) {
	sb.Reset()
}

// ReviewBufferWrite writes value with direct woven bytes.Buffer calls.
func ReviewBufferWrite(b *bytes.Buffer, value string) string {
	b.WriteString(value)
	out := b.String()
	return out
}

// ReviewBufferReset is a direct woven bytes.Buffer.Reset call.
func ReviewBufferReset(b *bytes.Buffer) {
	b.Reset()
}

// ReviewBufferString is a direct woven bytes.Buffer.String call.
func ReviewBufferString(b *bytes.Buffer) string {
	out := b.String()
	return out
}

// ReviewNewBufferString wraps an existing slice and calls a direct woven String.
func ReviewNewBufferString(backing []byte) string {
	b := bytes.NewBuffer(backing)
	out := b.String()
	return out
}
