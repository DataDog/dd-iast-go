// Reproducer for fx-hooks-yml-strings-F1: valid Go using method expressions.
package control

import (
	"bytes"
	"strings"
)

// Direct calls and method expressions not in call position (positive controls).
func Build(s string) string {
	var b strings.Builder
	b.WriteString(s)
	var buf bytes.Buffer
	buf.WriteString(b.String())
	f := (*strings.Replacer).Replace   // method value of a method expression, not a call
	g := ((*bytes.Buffer).WriteString) // parenthesized method expression
	g(&buf, "!")
	return f(strings.NewReplacer(",", ";"), buf.String())
}
