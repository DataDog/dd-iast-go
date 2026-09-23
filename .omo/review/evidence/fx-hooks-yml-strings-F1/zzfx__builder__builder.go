// Reproducer for fx-hooks-yml-strings-F1: valid Go using method expressions.
package builder

import "strings"

// Build writes through pointer method expressions on strings.Builder.
func Build(s string) string {
	var b strings.Builder
	(*strings.Builder).WriteString(&b, s)
	(*strings.Builder).WriteByte(&b, '!')
	return (*strings.Builder).String(&b)
}
