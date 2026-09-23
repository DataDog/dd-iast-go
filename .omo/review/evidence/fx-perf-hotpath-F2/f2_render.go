// Review-only woven fixture for fx-perf-hotpath-F2.
package overhead

import (
	"bytes"
	"strings"
)

// RenderClean is ordinary customer code: a clean template assembled with a
// Builder and a Buffer. Under Orchestrion every call below is woven.
func RenderClean(parts []string) (string, string) {
	var sb strings.Builder
	var bb bytes.Buffer
	for _, p := range parts {
		sb.WriteString(p)
		sb.WriteByte(',')
		bb.WriteString(p)
		bb.WriteByte(',')
	}
	return sb.String(), bb.String()
}
