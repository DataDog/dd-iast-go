// Reproducer for fx-hooks-yml-strings-F1: valid Go using method expressions.
package buffer

import "bytes"

// Build writes through pointer method expressions on bytes.Buffer.
func Build(s string) string {
	var b bytes.Buffer
	(*bytes.Buffer).Grow(&b, 16)
	(*bytes.Buffer).WriteString(&b, s)
	return (*bytes.Buffer).String(&b)
}
