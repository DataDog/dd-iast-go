package testapp

import "bytes"

// FxInteriorScratchBuffer mirrors an ordinary customer pattern: a Buffer is
// created over a small full-slice view of a much larger caller scratch
// allocation, tainted input is written, and the buffer contents are returned.
// All customer references to the scratch allocation and to the Buffer are
// dropped on return, so any surviving reference is held by IAST state.
func FxInteriorScratchBuffer(input string) string {
	scratch := make([]byte, 16<<20)
	buffer := bytes.NewBuffer(scratch[:0:16])
	buffer.WriteString(input)
	return buffer.String()
}
