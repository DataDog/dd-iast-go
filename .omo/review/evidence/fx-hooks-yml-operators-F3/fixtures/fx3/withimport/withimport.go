package withimport

import "strings"

// Hello is identical to greet.Hello but the package has one import.
func Hello(name string) string { return strings.TrimSpace("hello, " + name) }
