package pmethod

import (
	"bytes"
	"strings"
)

// Method values (documented unsupported) and user types with stdlib-like method names.
type W struct{ buf []byte }

func (w *W) WriteString(s string) (int, error) { w.buf = append(w.buf, s...); return len(s), nil }
func (w *W) String() string                    { return string(w.buf) }

func Run(s string) string {
	var sb strings.Builder
	ws := sb.WriteString
	ws(s)
	var w W
	w.WriteString(s)
	var bb bytes.Buffer
	wr := bb.Write
	wr([]byte(s))
	return sb.String() + w.String() + bb.String()
}
