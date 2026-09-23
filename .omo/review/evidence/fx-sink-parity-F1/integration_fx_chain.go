package testapp

import "strings"

func FXBoundaryQuery(sort string, prefixLen int) string {
	base := "SELECT id, name FROM users ORDER BY "
	pad := strings.Repeat(" ", prefixLen-len(base))
	return base + pad + sort
}
