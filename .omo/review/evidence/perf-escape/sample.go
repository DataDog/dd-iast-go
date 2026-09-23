package perfsample

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

var table = map[string]int{"GET:/a": 1}

// ConcatLocal: concat result used only locally (map lookup key via variable).
//
//go:noinline
func ConcatLocal(method, path string) int {
	key := method + ":" + path
	return table[key]
}

// ConvLocal: []byte->string assignment used only locally.
//
//go:noinline
func ConvLocal(b []byte) bool {
	s := string(b)
	return s == "GET"
}

// ByteSliceLocal: stack scratch buffer resliced (read-loop idiom).
//
//go:noinline
func ByteSliceLocal(src []byte) int {
	buf := make([]byte, 64)
	n := copy(buf, src)
	chunk := buf[:n]
	sum := 0
	for _, c := range chunk {
		sum += int(c)
	}
	return sum
}

// StringSliceLocal: slicing a string that came from a local conversion.
//
//go:noinline
func StringSliceLocal(b []byte) int {
	s := string(b)
	return len(s[1:])
}

// BuilderLocal: stack strings.Builder, result returned (escapes anyway).
//
//go:noinline
func BuilderLocal(a, b string) string {
	var sb strings.Builder
	sb.WriteString(a)
	sb.WriteString(b)
	return sb.String()
}

// BufferLocal: stack bytes.Buffer used for length only.
//
//go:noinline
func BufferLocal(a string) int {
	var buf bytes.Buffer
	buf.WriteString(a)
	buf.WriteByte('x')
	return buf.Len()
}

// JoinLocal: local slice literal joined.
//
//go:noinline
func JoinLocal(a, b string) int {
	return len(strings.Join([]string{a, b}, ","))
}

// SprintfLocal: fmt.Sprintf with a string argument.
//
//go:noinline
func SprintfLocal(a string) int {
	return len(fmt.Sprintf("x=%s", a))
}

// CutLocal: strings.Cut, pure window.
//
//go:noinline
func CutLocal(a string) int {
	before, after, _ := strings.Cut(a, "=")
	return len(before) + len(after)
}

// TrimLocal: strings.TrimSpace, pure window.
//
//go:noinline
func TrimLocal(a string) int {
	return len(strings.TrimSpace(a))
}

// SplitSeqLocal: range over strings.SplitSeq.
//
//go:noinline
func SplitSeqLocal(a string) int {
	n := 0
	for part := range strings.SplitSeq(a, ",") {
		n += len(part)
	}
	return n
}

// FieldsSeqLocal: range over strings.FieldsSeq.
//
//go:noinline
func FieldsSeqLocal(a string) int {
	n := 0
	for part := range strings.FieldsSeq(a) {
		n += len(part)
	}
	return n
}

// QuoteLocal: strconv.Quote.
//
//go:noinline
func QuoteLocal(a string) int {
	return len(strconv.Quote(a))
}

// ToLowerLocal: strings.ToLower on already-lowercase input (no alloc natively).
//
//go:noinline
func ToLowerLocal(a string) int {
	return len(strings.ToLower(a))
}

// ConcatLocal2..16: concat arity sweep, result used locally.
//
//go:noinline
func ConcatLocal2(a, b string) int { k := a + b; return table[k] }

//go:noinline
func ConcatLocal4(a, b string) int { k := a + b + a + b; return table[k] }

//go:noinline
func ConcatLocal5(a, b string) int { k := a + b + a + b + a; return table[k] }

//go:noinline
func ConcatLocal8(a, b string) int { k := a + b + a + b + a + b + a + b; return table[k] }

//go:noinline
func ConcatLocal16(a, b string) int {
	k := a + b + a + b + a + b + a + b + a + b + a + b + a + b + a + b
	return table[k]
}

// ConcatConvOperand: []byte->string conversion as a concat operand.
//
//go:noinline
func ConcatConvOperand(b []byte) int {
	k := string(b) + ":x"
	return table[k]
}

//go:noinline
func count(seq func(func(string) bool)) int {
	n := 0
	for s := range seq {
		n += len(s)
	}
	return n
}

// SplitSeqPass: iterator passed to another function.
//
//go:noinline
func SplitSeqPass(a string) int {
	return count(strings.SplitSeq(a, ","))
}

// BufferStringLocal: bytes.Buffer.String() used locally.
//
//go:noinline
func BufferStringLocal(buf *bytes.Buffer) bool {
	s := buf.String()
	return s == "abc"
}

// BuilderStringLocal: strings.Builder.String() on an escaping builder.
//
//go:noinline
func BuilderStringLocal(sb *strings.Builder) int {
	return len(sb.String())
}
