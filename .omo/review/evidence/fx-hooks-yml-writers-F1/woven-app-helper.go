package testapp

import "bytes"

// BufferWriteIntoLargeBacking writes tainted input into a small view of a
// caller-owned allocation and leaves the writer available only to instrumentation.
func BufferWriteIntoLargeBacking(input []byte) (int, error) {
	backing := make([]byte, 16<<20)
	buffer := bytes.NewBuffer(backing[:0:16])
	return buffer.Write(input)
}
