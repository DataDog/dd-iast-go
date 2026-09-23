// Reproducer for fx-hooks-yml-strings-F1: valid Go using method expressions.
package replacer

import str "strings"

var r = str.NewReplacer(",", ";")

// Replace calls strings.Replacer.Replace through a method expression, via an import alias.
func Replace(s string) string {
	return (*str.Replacer).Replace(r, s)
}
