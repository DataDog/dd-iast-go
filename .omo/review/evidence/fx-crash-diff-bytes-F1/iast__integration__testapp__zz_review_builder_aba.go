package testapp

import (
	"fmt"
	"strings"
)

// RowWriter is an ordinary reusable holder, as a handler would keep for rows.
type RowWriter struct{ SB strings.Builder }

// WriteRow is a direct (woven) strings.Builder write.
func (w *RowWriter) WriteRow(s string) { w.SB.WriteString(s) }

// ZeroReset reinitialises the holder with a zero value (not a hooked op).
func (w *RowWriter) ZeroReset() { *w = RowWriter{} }

// WovenReset uses the hooked strings.Builder.Reset.
func (w *RowWriter) WovenReset() { w.SB.Reset() }

// FormatRow writes through io.Writer (fmt.Fprintf is not wrapped).
func (w *RowWriter) FormatRow(s string) { fmt.Fprintf(&w.SB, "%s", s) }

// Row is a direct (woven) strings.Builder.String call.
func (w *RowWriter) Row() string { return w.SB.String() }
