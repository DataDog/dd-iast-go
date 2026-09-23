package pvariadic

import (
	. "bytes"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func pair(a, b string, ok bool) string { return fmt.Sprint(a, b, ok) }

func unescape(s string) (string, error) { return url.QueryUnescape(s) }

func Run(s string, args ...any) string {
	a := fmt.Sprintf("%s:%v", append([]any{s}, args...)...)
	b := fmt.Sprint()
	c := pair(strings.Cut(s, "="))
	d, _ := unescape(s)
	f := strings.ToUpper
	g := strings.NewReplacer("a", "b").Replace(s)
	h := string(ToUpper([]byte(s)))
	i := strconv.Quote(s)
	var parts []string
	parts = append(parts, strings.Fields(s)...)
	j := strings.Join(parts, ",")
	k := fmt.Sprintln(strings.SplitN(s, "=", 2))
	return a + b + c + d + f(s) + g + h + i + j + k
}
