package textutil

import "strings"

var _ = strings.ToUpper

func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
