package testapp

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// CountingStringer counts String invocations.
type CountingStringer struct {
	Calls *int
	Value string
}

func (c CountingStringer) String() string { *c.Calls++; return c.Value }

// CountingFormatter counts Format invocations.
type CountingFormatter struct {
	Calls *int
	Value string
}

func (c CountingFormatter) Format(f fmt.State, verb rune) { *c.Calls++; _, _ = f.Write([]byte(c.Value)) }

// CountingError counts Error invocations.
type CountingError struct {
	Calls *int
	Value string
}

func (c CountingError) Error() string { *c.Calls++; return c.Value }

// RedactedSecret is a named string whose String method never exposes its value.
type RedactedSecret string

func (RedactedSecret) String() string { return "[redacted]" }

// ConstFormatter is a named string whose Format method never exposes its value.
type ConstFormatter string

func (ConstFormatter) Format(f fmt.State, verb rune) { _, _ = f.Write([]byte("constant")) }

// Holder carries a tainted field.
type Holder struct{ Field string }

// Wrap is a Stringer returning its tainted field.
type Wrap struct{ S string }

func (w Wrap) String() string { return w.S }

func two() (string, string) { return "ab", "cd" }

// SortOrder is an allowlist type: String only ever returns constants.
type SortOrder string

func (s SortOrder) String() string {
	if s == "desc" {
		return "DESC"
	}
	return "ASC"
}

// ReviewOrderQuery builds a query using the allowlisted sort order.
func ReviewOrderQuery(order string) string {
	return fmt.Sprintf("SELECT id FROM users ORDER BY name %s", SortOrder(order))
}

// ReviewBuilderFprintf writes tainted then clean data via Fprintf.
func ReviewBuilderFprintf(tainted, clean string) string {
	var b strings.Builder
	b.WriteString(tainted)
	fmt.Fprintf(&b, "-%s", clean)
	b.WriteString("!")
	return b.String()
}

// ReviewBuilderFprintfFirst writes clean data via Fprintf then tainted data.
func ReviewBuilderFprintfFirst(tainted, clean string) string {
	var b strings.Builder
	b.WriteString("x")
	fmt.Fprintf(&b, "%s-", clean)
	b.WriteString(tainted)
	return b.String()
}

func ReviewSprintMulti() string                      { return fmt.Sprint(two()) }
func ReviewSprint(arguments ...any) string           { return fmt.Sprint(arguments...) }
func ReviewSprintf(f string, arguments ...any) string { return fmt.Sprintf(f, arguments...) }
func ReviewSprintfType(v any) string                 { return fmt.Sprintf("SELECT %T", v) }
func ReviewSprintfZeroPrecision(v string) string     { return fmt.Sprintf("SELECT 1%.0s", v) }
func ReviewSprintfIndexed(v string) string           { return fmt.Sprintf("SELECT %[2]s", v, "safe") }
func ReviewSprintfTwo(a, b string) string {
	return fmt.Sprintf("SELECT * FROM t WHERE a='%s' AND b='%s'", a, b)
}
func ReviewQuoteWrap(v string) string            { return "\"" + v + "\"" }
func ReviewUnquote(v string) (string, error)     { return strconv.Unquote(v) }
func ReviewQueryUnescape(v string) (string, error) { return url.QueryUnescape(v) }
func ReviewQueryEscape(v string) string          { return url.QueryEscape(v) }
func ReviewPrefix(v string) string               { return "ab" + v + "cd" }
