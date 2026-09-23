// Differential fidelity harness (review node hooks-fidelity-strings).
// Calls every iast/propagation strings/fmt/strconv/url/operator wrapper
// directly and the uninstrumented stdlib/native operation with identical
// inputs, in four modes, and asserts identical results and panics.
// Run WITHOUT orchestrion so the reference calls stay native.

package propagation_test

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"math"
	"math/bits"
	"math/rand/v2"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
	"unsafe"

	iastprop "github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

type diffMode int

const (
	modeInactive diffMode = iota
	modeActiveClean
	modeTainted
	modeForeign
)

func (m diffMode) String() string {
	return [...]string{"inactive", "active-clean", "tainted", "foreign-owners"}[m]
}

type outcome struct {
	vals     []any
	panicked bool
	pv       string
}

func capture(f func() []any) (o outcome) {
	defer func() {
		if r := recover(); r != nil {
			o.panicked = true
			o.pv = fmt.Sprintf("%T: %v", r, r)
		}
	}()
	o.vals = normalize(f())
	return
}

// normalize makes values comparable while preserving caller-visible shape
// (slice len/cap, error type+message, byte-slice backing identity is checked
// separately where relevant).
func normalize(vals []any) []any {
	out := make([]any, 0, len(vals))
	for _, v := range vals {
		switch x := v.(type) {
		case error:
			out = append(out, fmt.Sprintf("err %T: %v", x, x))
			var ue url.EscapeError
			if errors.As(x, &ue) {
				out = append(out, string(ue))
			}
		case []string:
			out = append(out, fmt.Sprintf("slice len=%d cap=%d nil=%v", len(x), cap(x), x == nil), slices.Clone(x))
		case nil:
			out = append(out, "<nil>")
		default:
			out = append(out, v)
		}
	}
	return out
}

func collectSeq(seq iter.Seq[string]) []any {
	all := slices.Collect(seq)
	var first2 []string
	for v := range seq {
		first2 = append(first2, v)
		if len(first2) == 2 {
			break
		}
	}
	// A body panic must propagate identically.
	var bodyPanic string
	func() {
		defer func() {
			if r := recover(); r != nil {
				bodyPanic = fmt.Sprint(r)
			}
		}()
		for v := range seq {
			if v != "" || true {
				panic("body:" + v)
			}
		}
	}()
	return []any{all, first2, bodyPanic}
}

// counting predicates: returned count must match between std and wrapper.
type counter struct{ n int }

func (c *counter) space(r rune) bool { c.n++; return unicode.IsSpace(r) }
func (c *counter) comma(r rune) bool { c.n++; return r == ',' || r == 0xFFFD }
func (c *counter) mapr(r rune) rune {
	c.n++
	switch {
	case r == 'a':
		return -1
	case r == 'b':
		return utf8Bad
	case r == 'c':
		return 0x10FFFF + 1
	}
	return unicode.ToUpper(r)
}

const utf8Bad = 0xD800 // surrogate, invalid rune

type strCase struct {
	name  string
	nstr  int
	std   func(s []string, n int) []any
	wrap  func(s []string, n int) []any
	count func(r *rand.Rand, s []string) int // nil -> n unused
}

var huge = []int{-1, 0, 1, 2, 3, 7, 33, 100, math.MaxInt, math.MinInt, math.MaxInt/2 + 1, 1 << 31}

func pickCount(r *rand.Rand) int {
	if r.IntN(3) == 0 {
		return huge[r.IntN(len(huge))]
	}
	return r.IntN(40) - 3
}

// safeRepeatCount avoids counts that would request an allocation that does not
// overflow but is too large to satisfy (fatal, unrecoverable in both).
func safeRepeatCount(r *rand.Rand, s []string) int {
	n := pickCount(r)
	if n <= 0 || len(s[0]) == 0 {
		return n
	}
	hi, lo := bits.Mul(uint(len(s[0])), uint(n))
	if hi > 0 || lo > uint(math.MaxInt) {
		return n // overflow: both must panic identically
	}
	if lo > 1<<20 {
		return r.IntN(3)
	}
	return n
}

func strCases() []strCase {
	return []strCase{
		{name: "Clone", nstr: 1,
			std:  func(s []string, _ int) []any { return []any{strings.Clone(s[0])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StringsClone(s[0])} }},
		{name: "Cut", nstr: 2,
			std: func(s []string, _ int) []any { a, b, c := strings.Cut(s[0], s[1]); return []any{a, b, c} },
			wrap: func(s []string, _ int) []any {
				a, b, c := iastprop.StringsCut(s[0], s[1])
				return []any{a, b, c}
			}},
		{name: "CutPrefix", nstr: 2,
			std:  func(s []string, _ int) []any { a, b := strings.CutPrefix(s[0], s[1]); return []any{a, b} },
			wrap: func(s []string, _ int) []any { a, b := iastprop.StringsCutPrefix(s[0], s[1]); return []any{a, b} }},
		{name: "CutSuffix", nstr: 2,
			std:  func(s []string, _ int) []any { a, b := strings.CutSuffix(s[0], s[1]); return []any{a, b} },
			wrap: func(s []string, _ int) []any { a, b := iastprop.StringsCutSuffix(s[0], s[1]); return []any{a, b} }},
		{name: "Split", nstr: 2,
			std:  func(s []string, _ int) []any { return []any{strings.Split(s[0], s[1])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StringsSplit(s[0], s[1])} }},
		{name: "SplitN", nstr: 2, count: func(r *rand.Rand, _ []string) int { return pickCount(r) },
			std:  func(s []string, n int) []any { return []any{strings.SplitN(s[0], s[1], n)} },
			wrap: func(s []string, n int) []any { return []any{iastprop.StringsSplitN(s[0], s[1], n)} }},
		{name: "SplitAfter", nstr: 2,
			std:  func(s []string, _ int) []any { return []any{strings.SplitAfter(s[0], s[1])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StringsSplitAfter(s[0], s[1])} }},
		{name: "SplitAfterN", nstr: 2, count: func(r *rand.Rand, _ []string) int { return pickCount(r) },
			std:  func(s []string, n int) []any { return []any{strings.SplitAfterN(s[0], s[1], n)} },
			wrap: func(s []string, n int) []any { return []any{iastprop.StringsSplitAfterN(s[0], s[1], n)} }},
		{name: "SplitSeq", nstr: 2,
			std:  func(s []string, _ int) []any { return collectSeq(strings.SplitSeq(s[0], s[1])) },
			wrap: func(s []string, _ int) []any { return collectSeq(iastprop.StringsSplitSeq(s[0], s[1])) }},
		{name: "SplitAfterSeq", nstr: 2,
			std:  func(s []string, _ int) []any { return collectSeq(strings.SplitAfterSeq(s[0], s[1])) },
			wrap: func(s []string, _ int) []any { return collectSeq(iastprop.StringsSplitAfterSeq(s[0], s[1])) }},
		{name: "Lines", nstr: 1,
			std:  func(s []string, _ int) []any { return collectSeq(strings.Lines(s[0])) },
			wrap: func(s []string, _ int) []any { return collectSeq(iastprop.StringsLines(s[0])) }},
		{name: "Fields", nstr: 1,
			std:  func(s []string, _ int) []any { return []any{strings.Fields(s[0])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StringsFields(s[0])} }},
		{name: "FieldsFunc", nstr: 1,
			std: func(s []string, _ int) []any {
				c := &counter{}
				return []any{strings.FieldsFunc(s[0], c.comma), c.n}
			},
			wrap: func(s []string, _ int) []any {
				c := &counter{}
				return []any{iastprop.StringsFieldsFunc(s[0], c.comma), c.n}
			}},
		{name: "FieldsSeq", nstr: 1,
			std:  func(s []string, _ int) []any { return collectSeq(strings.FieldsSeq(s[0])) },
			wrap: func(s []string, _ int) []any { return collectSeq(iastprop.StringsFieldsSeq(s[0])) }},
		{name: "FieldsFuncSeq", nstr: 1,
			std: func(s []string, _ int) []any {
				c := &counter{}
				return append(collectSeq(strings.FieldsFuncSeq(s[0], c.space)), c.n)
			},
			wrap: func(s []string, _ int) []any {
				c := &counter{}
				return append(collectSeq(iastprop.StringsFieldsFuncSeq(s[0], c.space)), c.n)
			}},
		{name: "Join2", nstr: 3,
			std:  func(s []string, _ int) []any { return []any{strings.Join(s[:2], s[2])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StringsJoin(s[:2], s[2])} }},
		{name: "JoinMany", nstr: 1,
			std: func(s []string, n int) []any {
				return []any{strings.Join(slices.Repeat([]string{s[0]}, (n&31)+1), ",")}
			},
			count: func(r *rand.Rand, _ []string) int { return r.IntN(40) },
			wrap: func(s []string, n int) []any {
				return []any{iastprop.StringsJoin(slices.Repeat([]string{s[0]}, (n&31)+1), ",")}
			}},
		{name: "JoinNilEmpty", nstr: 1,
			std: func(s []string, _ int) []any {
				return []any{strings.Join(nil, s[0]), strings.Join([]string{}, s[0]), strings.Join([]string{"", s[0], ""}, "")}
			},
			wrap: func(s []string, _ int) []any {
				return []any{iastprop.StringsJoin(nil, s[0]), iastprop.StringsJoin([]string{}, s[0]), iastprop.StringsJoin([]string{"", s[0], ""}, "")}
			}},
		{name: "Repeat", nstr: 1, count: safeRepeatCount,
			std:  func(s []string, n int) []any { return []any{strings.Repeat(s[0], n)} },
			wrap: func(s []string, n int) []any { return []any{iastprop.StringsRepeat(s[0], n)} }},
		{name: "Replace", nstr: 3, count: func(r *rand.Rand, _ []string) int { return pickCount(r) },
			std:  func(s []string, n int) []any { return []any{strings.Replace(s[0], s[1], s[2], n)} },
			wrap: func(s []string, n int) []any { return []any{iastprop.StringsReplace(s[0], s[1], s[2], n)} }},
		{name: "ReplaceAll", nstr: 3,
			std:  func(s []string, _ int) []any { return []any{strings.ReplaceAll(s[0], s[1], s[2])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StringsReplaceAll(s[0], s[1], s[2])} }},
		{name: "ReplacerReplace", nstr: 3,
			std: func(s []string, _ int) []any {
				return []any{strings.NewReplacer(s[1], s[2], "a", "A").Replace(s[0])}
			},
			wrap: func(s []string, _ int) []any {
				return []any{iastprop.ReplacerReplace(strings.NewReplacer(s[1], s[2], "a", "A"), s[0])}
			}},
		{name: "ReplacerNil", nstr: 1,
			std: func(s []string, _ int) []any {
				var r *strings.Replacer
				return []any{r.Replace(s[0])}
			},
			wrap: func(s []string, _ int) []any { return []any{iastprop.ReplacerReplace(nil, s[0])} }},
		{name: "ReplacerZero", nstr: 1,
			std: func(s []string, _ int) []any {
				var r strings.Replacer
				return []any{r.Replace(s[0])}
			},
			wrap: func(s []string, _ int) []any {
				var r strings.Replacer
				return []any{iastprop.ReplacerReplace(&r, s[0])}
			}},
		{name: "Trim", nstr: 2,
			std:  func(s []string, _ int) []any { return []any{strings.Trim(s[0], s[1])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StringsTrim(s[0], s[1])} }},
		{name: "TrimSpace", nstr: 1,
			std:  func(s []string, _ int) []any { return []any{strings.TrimSpace(s[0])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StringsTrimSpace(s[0])} }},
		{name: "TrimLeft", nstr: 2,
			std:  func(s []string, _ int) []any { return []any{strings.TrimLeft(s[0], s[1])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StringsTrimLeft(s[0], s[1])} }},
		{name: "TrimRight", nstr: 2,
			std:  func(s []string, _ int) []any { return []any{strings.TrimRight(s[0], s[1])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StringsTrimRight(s[0], s[1])} }},
		{name: "TrimPrefix", nstr: 2,
			std:  func(s []string, _ int) []any { return []any{strings.TrimPrefix(s[0], s[1])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StringsTrimPrefix(s[0], s[1])} }},
		{name: "TrimSuffix", nstr: 2,
			std:  func(s []string, _ int) []any { return []any{strings.TrimSuffix(s[0], s[1])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StringsTrimSuffix(s[0], s[1])} }},
		{name: "TrimFunc", nstr: 1,
			std: func(s []string, _ int) []any { c := &counter{}; return []any{strings.TrimFunc(s[0], c.space), c.n} },
			wrap: func(s []string, _ int) []any {
				c := &counter{}
				return []any{iastprop.StringsTrimFunc(s[0], c.space), c.n}
			}},
		{name: "TrimLeftFunc", nstr: 1,
			std: func(s []string, _ int) []any { c := &counter{}; return []any{strings.TrimLeftFunc(s[0], c.space), c.n} },
			wrap: func(s []string, _ int) []any {
				c := &counter{}
				return []any{iastprop.StringsTrimLeftFunc(s[0], c.space), c.n}
			}},
		{name: "TrimRightFunc", nstr: 1,
			std: func(s []string, _ int) []any {
				c := &counter{}
				return []any{strings.TrimRightFunc(s[0], c.space), c.n}
			},
			wrap: func(s []string, _ int) []any {
				c := &counter{}
				return []any{iastprop.StringsTrimRightFunc(s[0], c.space), c.n}
			}},
		{name: "ToLower", nstr: 1,
			std:  func(s []string, _ int) []any { return []any{strings.ToLower(s[0])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StringsToLower(s[0])} }},
		{name: "ToUpper", nstr: 1,
			std:  func(s []string, _ int) []any { return []any{strings.ToUpper(s[0])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StringsToUpper(s[0])} }},
		{name: "ToTitle", nstr: 1,
			std:  func(s []string, _ int) []any { return []any{strings.ToTitle(s[0])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StringsToTitle(s[0])} }},
		{name: "Map", nstr: 1,
			std:  func(s []string, _ int) []any { c := &counter{}; return []any{strings.Map(c.mapr, s[0]), c.n} },
			wrap: func(s []string, _ int) []any { c := &counter{}; return []any{iastprop.StringsMap(c.mapr, s[0]), c.n} }},
		{name: "MapPanics", nstr: 1,
			std: func(s []string, _ int) []any {
				return []any{strings.Map(func(r rune) rune {
					if r == ',' {
						panic("map:,")
					}
					return r
				}, s[0])}
			},
			wrap: func(s []string, _ int) []any {
				return []any{iastprop.StringsMap(func(r rune) rune {
					if r == ',' {
						panic("map:,")
					}
					return r
				}, s[0])}
			}},
		{name: "ToValidUTF8", nstr: 2,
			std:  func(s []string, _ int) []any { return []any{strings.ToValidUTF8(s[0], s[1])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StringsToValidUTF8(s[0], s[1])} }},
		{name: "QueryEscape", nstr: 1,
			std:  func(s []string, _ int) []any { return []any{url.QueryEscape(s[0])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.URLQueryEscape(s[0])} }},
		{name: "PathEscape", nstr: 1,
			std:  func(s []string, _ int) []any { return []any{url.PathEscape(s[0])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.URLPathEscape(s[0])} }},
		{name: "QueryUnescape", nstr: 1,
			std:  func(s []string, _ int) []any { a, e := url.QueryUnescape(s[0]); return []any{a, e} },
			wrap: func(s []string, _ int) []any { a, e := iastprop.URLQueryUnescape(s[0]); return []any{a, e} }},
		{name: "PathUnescape", nstr: 1,
			std:  func(s []string, _ int) []any { a, e := url.PathUnescape(s[0]); return []any{a, e} },
			wrap: func(s []string, _ int) []any { a, e := iastprop.URLPathUnescape(s[0]); return []any{a, e} }},
		{name: "Quote", nstr: 1,
			std:  func(s []string, _ int) []any { return []any{strconv.Quote(s[0])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StrconvQuote(s[0])} }},
		{name: "QuoteToASCII", nstr: 1,
			std:  func(s []string, _ int) []any { return []any{strconv.QuoteToASCII(s[0])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StrconvQuoteToASCII(s[0])} }},
		{name: "QuoteToGraphic", nstr: 1,
			std:  func(s []string, _ int) []any { return []any{strconv.QuoteToGraphic(s[0])} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.StrconvQuoteToGraphic(s[0])} }},
		{name: "Unquote", nstr: 1,
			std:  func(s []string, _ int) []any { a, e := strconv.Unquote(s[0]); return []any{a, e} },
			wrap: func(s []string, _ int) []any { a, e := iastprop.StrconvUnquote(s[0]); return []any{a, e} }},
		{name: "UnquoteQuoted", nstr: 1,
			std: func(s []string, _ int) []any {
				q := `"` + s[0] + `"`
				a, e := strconv.Unquote(q)
				return []any{a, e}
			},
			wrap: func(s []string, _ int) []any {
				q := `"` + s[0] + `"`
				a, e := iastprop.StrconvUnquote(q)
				return []any{a, e}
			}},
	}
}

// Formatting args: exercise Stringer call counts, panicking Stringers, nil,
// []byte, named string/byte types, pointers.
type namedStr string
type namedBytes []byte
type namedByte byte

// countingStringer counts String calls in a package counter (no per-call
// pointer so address-printing verbs stay identical between std and wrapper).
var fmtCount int

type countingStringer struct{ v string }

func (c countingStringer) String() string { fmtCount++; return c.v }

type panicStringer struct{}

func (panicStringer) String() string { panic("stringer boom") }

type nilPtrStringer struct{ v string }

func (p *nilPtrStringer) String() string { return p.v } // nil receiver -> nil deref, fmt prints <nil>

func fmtArgs(s []string, n *int) []any {
	fmtCount = 0
	_ = n
	var nilBytes []byte
	var nps *nilPtrStringer
	return []any{
		s[0], []byte(s[1]), namedStr(s[1]), namedBytes(s[0]), []namedByte(s[0]), nil, nilBytes,
		countingStringer{s[1]}, panicStringer{}, nps, sharedErr, 42, struct{ A string }{s[1]},
		sharedMap, [2]string{s[0], s[1]},
	}
}

// Pointer-carrying args are shared between the std and wrapper calls so that
// address-printing verbs produce identical output.
var (
	sharedErr error
	sharedMap map[string]string
)

func fmtCases() []strCase {
	return []strCase{
		{name: "Sprint", nstr: 2,
			std: func(s []string, _ int) []any { n := 0; r := fmt.Sprint(fmtArgs(s, &n)...); return []any{r, fmtCount} },
			wrap: func(s []string, _ int) []any {
				n := 0
				r := iastprop.FmtSprint(fmtArgs(s, &n)...)
				return []any{r, fmtCount}
			}},
		{name: "Sprintln", nstr: 2,
			std: func(s []string, _ int) []any { n := 0; r := fmt.Sprintln(fmtArgs(s, &n)...); return []any{r, fmtCount} },
			wrap: func(s []string, _ int) []any {
				n := 0
				r := iastprop.FmtSprintln(fmtArgs(s, &n)...)
				return []any{r, fmtCount}
			}},
		{name: "SprintfFmt", nstr: 3,
			std: func(s []string, _ int) []any {
				n := 0
				r := fmt.Sprintf(s[2]+"%s|%q|%v|%x|%d|%[1]*s|%!|%", fmtArgs(s, &n)...)
				return []any{r, fmtCount}
			},
			wrap: func(s []string, _ int) []any {
				n := 0
				r := iastprop.FmtSprintf(s[2]+"%s|%q|%v|%x|%d|%[1]*s|%!|%", fmtArgs(s, &n)...)
				return []any{r, fmtCount}
			}},
		{name: "SprintfTaintedFormat", nstr: 2,
			std:  func(s []string, _ int) []any { return []any{fmt.Sprintf(s[0], s[1], 3)} },
			wrap: func(s []string, _ int) []any { return []any{iastprop.FmtSprintf(s[0], s[1], 3)} }},
		{name: "SprintEmpty", nstr: 1,
			std: func(s []string, _ int) []any {
				return []any{fmt.Sprint(), fmt.Sprintln(), fmt.Sprintf(s[0]), fmt.Sprint(nil), fmt.Sprint([]any{s[0]}...)}
			},
			wrap: func(s []string, _ int) []any {
				return []any{iastprop.FmtSprint(), iastprop.FmtSprintln(), iastprop.FmtSprintf(s[0]), iastprop.FmtSprint(nil), iastprop.FmtSprint([]any{s[0]}...)}
			}},
	}
}

var alphabet = []string{
	"a", "b", "c", "A", ",", " ", "\t", "\n", "\r\n", "%", "%2", "%zz", "%41", "+", "\"", "\\", "'", "`",
	"é", "ß", "İ", "ǅ", "ﬀ", "日本", "\u2028", "\u00a0", "\x00", "\xff", "\xc3", "\xe2\x82", "\xed\xa0\x80",
	"\\x41", "\\u00e9", "\\U0001F600", "\\n", "ab", "abc", "::", "=", "/", "?", "&", "\U0001F600", "a,b",
}

func genString(r *rand.Rand) string {
	switch r.IntN(20) {
	case 0:
		return ""
	case 1:
		return strings.Repeat("ab,", 23000) // > 64 KiB (MaxRootBytes)
	case 2:
		return strings.Repeat("x,", 40) // many matches (> 32 windows / replacements)
	}
	n := r.IntN(12)
	var b strings.Builder
	for range n {
		b.WriteString(alphabet[r.IntN(len(alphabet))])
	}
	return b.String()
}

var edgeStrings = []string{"", "a", ",", "ab", "a,b", " a b ", "\xff", "\xff\xfe", "\xc3", "ÀÁ", "İ", "ǅǆ",
	"%", "%zz", "%2", "a+b%20c", `"abc"`, `"\xff"`, "`raw`", "'a'", `"unterminated`, "\n\n", "a\nb\r\nc",
	strings.Repeat(",", 40), strings.Repeat("a", 65537)}

type diffEnv struct {
	t      *testing.T
	ctxs   []context.Context
	scopes []*request.Scope
}

func (e *diffEnv) begin(nOwners int) {
	for range nOwners {
		ctx, scope, created := request.Begin(context.Background())
		if !created {
			e.t.Fatalf("request.Begin did not create a scope")
		}
		e.ctxs = append(e.ctxs, ctx)
		e.scopes = append(e.scopes, scope)
	}
}

func (e *diffEnv) finish() {
	for _, s := range e.scopes {
		s.Finish()
	}
	e.ctxs, e.scopes = nil, nil
}

func (e *diffEnv) taintArgs(mode diffMode, in []string) (out []string, tainted int) {
	out = make([]string, len(in))
	for i, v := range in {
		switch mode {
		case modeInactive, modeActiveClean:
			out[i] = strings.Clone(v)
		case modeTainted:
			out[i] = taint.TaintString(e.ctxs[0], taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "p" + strconv.Itoa(i)}, v)
		case modeForeign:
			out[i] = taint.TaintString(e.ctxs[i%len(e.ctxs)], taint.Source{Origin: taint.OriginHttpRequestHeader, Name: "h" + strconv.Itoa(i)}, v)
		}
		if taint.IsTaintedString(out[i]) {
			tainted++
		}
	}
	return out, tainted
}

func withDiffConfig(t *testing.T) {
	pe, ps, pm := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() { config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = pe, ps, pm })
}

func diffIterations() int {
	if v, err := strconv.Atoi(os.Getenv("DIFF_ITERS")); err == nil {
		return v
	}
	return 3000
}

var currentCase atomic.Value

func memWatchdog(t *testing.T) {
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		var ms runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(200 * time.Millisecond):
			}
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > 3<<30 {
				panic(fmt.Sprintf("MEMORY WATCHDOG: HeapAlloc=%d MiB during case %v", ms.HeapAlloc>>20, currentCase.Load()))
			}
		}
	}()
}

func TestFidelityStringsDifferential(t *testing.T) {
	withDiffConfig(t)
	memWatchdog(t)
	seed := uint64(0x5eed1a57)
	if v, err := strconv.ParseUint(os.Getenv("DIFF_SEED"), 0, 64); err == nil {
		seed = v
	}
	t.Logf("seed=%#x iterations=%d", seed, diffIterations())
	cases := append(strCases(), fmtCases()...)
	type stat struct{ calls, taintedIn, taintedOut, panics int }
	stats := map[string]*stat{}
	divergences := 0
	for _, mode := range []diffMode{modeInactive, modeActiveClean, modeTainted, modeForeign} {
		r := rand.New(rand.NewPCG(seed, uint64(mode)))
		env := &diffEnv{t: t}
		if mode == modeInactive && request.ActiveStore() != nil {
			t.Fatalf("inactive mode requires no active store")
		}
		iters := diffIterations()
		for it := 0; it < iters+len(edgeStrings); it++ {
			if mode != modeInactive && it%25 == 0 {
				env.finish()
				owners := 1
				if mode == modeForeign {
					owners = 3
				}
				env.begin(owners)
			}
			for _, c := range cases {
				raw := make([]string, c.nstr)
				for i := range raw {
					if it < len(edgeStrings) {
						raw[i] = edgeStrings[(it+i*7)%len(edgeStrings)]
					} else {
						raw[i] = genString(r)
					}
				}
				// Harness guard: keep replacement expansion bounded (both sides would OOM).
				if c.nstr == 3 && (len(raw[0])+1)*len(raw[2]) > 1<<22 {
					raw[2] = raw[2][:16]
				}
				n := 0
				if c.count != nil {
					n = c.count(r, raw)
				}
				args, tin := env.taintArgs(mode, raw)
				sharedErr = errors.New(raw[0])
				sharedMap = map[string]string{"k": raw[0]}
				currentCase.Store(fmt.Sprintf("%s/%s it=%d n=%d lens=%v", mode, c.name, it, n, lens(raw)))
				ref := capture(func() []any { return c.std(raw, n) })
				got := capture(func() []any { return c.wrap(args, n) })
				key := mode.String() + "/" + c.name
				st := stats[key]
				if st == nil {
					st = &stat{}
					stats[key] = st
				}
				st.calls++
				st.taintedIn += tin
				if got.panicked {
					st.panics++
				}
				for _, v := range got.vals {
					var ss []string
					switch x := v.(type) {
					case string:
						ss = []string{x}
					case []string:
						ss = x
					}
					for _, s := range ss {
						if s != "" && taint.IsTaintedString(s) {
							st.taintedOut++
						}
					}
				}
				if ref.panicked != got.panicked || ref.pv != got.pv || !reflect.DeepEqual(ref.vals, got.vals) {
					divergences++
					if divergences <= 40 {
						t.Errorf("DIVERGENCE %s args=%q n=%d\n  std : panicked=%v pv=%q vals=%#v\n  wrap: panicked=%v pv=%q vals=%#v",
							key, raw, n, ref.panicked, ref.pv, trunc(ref.vals), got.panicked, got.pv, trunc(got.vals))
					}
				}
			}
		}
		env.finish()
		if request.ActiveStore() != nil && mode == modeInactive {
			t.Fatalf("store unexpectedly active")
		}
	}
	keys := make([]string, 0, len(stats))
	for k := range stats {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		s := stats[k]
		t.Logf("STAT %-40s calls=%d taintedInputs=%d taintedStringOutputs=%d panics=%d", k, s.calls, s.taintedIn, s.taintedOut, s.panics)
	}
	t.Logf("TOTAL divergences=%d", divergences)
	// Anti-silent-green: tainted modes must actually produce tainted outputs.
	for _, k := range []string{"tainted/Split", "tainted/Replace", "tainted/Sprint", "tainted/QueryEscape", "foreign-owners/Join2", "tainted/ToUpper"} {
		if stats[k] == nil || stats[k].taintedOut == 0 {
			t.Errorf("harness sanity: %s produced no tainted outputs", k)
		}
	}
}

func lens(s []string) []int {
	out := make([]int, len(s))
	for i, v := range s {
		out[i] = len(v)
	}
	return out
}

func trunc(v []any) string {
	s := fmt.Sprintf("%#v", v)
	if len(s) > 600 {
		return s[:600] + "..."
	}
	return s
}

// ---- operators: concat, slicing, bytes->string ----

func TestFidelityOperatorsDifferential(t *testing.T) {
	withDiffConfig(t)
	r := rand.New(rand.NewPCG(7, 11))
	divergences := 0
	tainted := 0
	check := func(name string, ref, got outcome) {
		if ref.panicked != got.panicked || ref.pv != got.pv || !reflect.DeepEqual(ref.vals, got.vals) {
			divergences++
			if divergences <= 40 {
				t.Errorf("DIVERGENCE %s\n std : %v %q %#v\n wrap: %v %q %#v", name, ref.panicked, ref.pv, ref.vals, got.panicked, got.pv, got.vals)
			}
		}
	}
	for _, mode := range []diffMode{modeInactive, modeTainted, modeForeign} {
		env := &diffEnv{t: t}
		for it := 0; it < 4000; it++ {
			if mode != modeInactive && it%25 == 0 {
				env.finish()
				env.begin(map[diffMode]int{modeTainted: 1, modeForeign: 3}[mode])
			}
			raw := make([]string, 16)
			for i := range raw {
				raw[i] = genString(r)
				if len(raw[i]) > 4096 {
					raw[i] = raw[i][:r.IntN(4096)]
				}
			}
			a, _ := env.taintArgs(mode, raw)
			for _, v := range a {
				if v != "" && taint.IsTaintedString(v) {
					tainted++
				}
			}
			check("Concat2", capture(func() []any { return []any{raw[0] + raw[1]} }), capture(func() []any { return []any{iastprop.Concat2(a[0], a[1])} }))
			check("Concat3", capture(func() []any { return []any{raw[0] + raw[1] + raw[2]} }), capture(func() []any { return []any{iastprop.Concat3(a[0], a[1], a[2])} }))
			check("Concat8", capture(func() []any { return []any{raw[0] + raw[1] + raw[2] + raw[3] + raw[4] + raw[5] + raw[6] + raw[7]} }),
				capture(func() []any { return []any{iastprop.Concat8(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7])} }))
			check("Concat16", capture(func() []any {
				return []any{raw[0] + raw[1] + raw[2] + raw[3] + raw[4] + raw[5] + raw[6] + raw[7] + raw[8] + raw[9] + raw[10] + raw[11] + raw[12] + raw[13] + raw[14] + raw[15]}
			}), capture(func() []any {
				return []any{iastprop.Concat16(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15])}
			}))
			check("Concat2Named", capture(func() []any { return []any{namedStr(raw[0]) + namedStr(raw[1])} }),
				capture(func() []any { return []any{iastprop.Concat2(namedStr(a[0]), namedStr(a[1]))} }))

			s, ts := raw[0], a[0]
			lo, hi := r.IntN(len(s)+3)-1, r.IntN(len(s)+3)-1
			check("StringSliceLow", capture(func() []any { return []any{s[lo:]} }), capture(func() []any { return []any{iastprop.StringSliceLow(ts, lo)} }))
			check("StringSliceHigh", capture(func() []any { return []any{s[:hi]} }), capture(func() []any { return []any{iastprop.StringSliceHigh(ts, hi)} }))
			check("StringSliceBounds", capture(func() []any { return []any{s[lo:hi]} }), capture(func() []any { return []any{iastprop.StringSliceBounds(ts, lo, hi)} }))
			check("StringSliceAll", capture(func() []any { return []any{s[:]} }), capture(func() []any { return []any{iastprop.StringSliceAll(ts)} }))
			ulo, uhi := uint(lo), uint8(hi)
			check("StringSliceUint", capture(func() []any { return []any{s[ulo:uhi]} }), capture(func() []any { return []any{iastprop.StringSliceBounds(ts, ulo, uhi)} }))
			i8 := int8(lo)
			check("StringSliceInt8", capture(func() []any { return []any{s[i8:]} }), capture(func() []any { return []any{iastprop.StringSliceLow(ts, i8)} }))

			// bytes: compare value, len, cap and backing identity
			var tb []byte
			bb := []byte(raw[1])
			bb = append(bb, "cap"...)
			bb = bb[:len(raw[1])]
			switch mode {
			case modeInactive:
				tb = bb
			default:
				tb = taint.TaintBytes(env.ctxs[0], taint.Source{Origin: taint.OriginHttpRequestBody, Name: "b"}, bb)
			}
			mx := r.IntN(cap(tb)+3) - 1
			blo, bhi := r.IntN(cap(tb)+3)-1, r.IntN(cap(tb)+3)-1
			bshape := func(b []byte) []any {
				return []any{string(b), len(b), cap(b), b == nil, uintptr(unsafe.Pointer(unsafe.SliceData(b))) - uintptr(unsafe.Pointer(unsafe.SliceData(tb)))}
			}
			check("BytesSliceLow", capture(func() []any { return bshape(tb[blo:]) }), capture(func() []any { return bshape(iastprop.BytesSliceLow(tb, blo)) }))
			check("BytesSliceHigh", capture(func() []any { return bshape(tb[:bhi]) }), capture(func() []any { return bshape(iastprop.BytesSliceHigh(tb, bhi)) }))
			check("BytesSliceBounds", capture(func() []any { return bshape(tb[blo:bhi]) }), capture(func() []any { return bshape(iastprop.BytesSliceBounds(tb, blo, bhi)) }))
			check("BytesSliceFull", capture(func() []any { return bshape(tb[blo:bhi:mx]) }), capture(func() []any { return bshape(iastprop.BytesSliceFull(tb, blo, bhi, mx)) }))
			check("BytesSliceFullZero", capture(func() []any { return bshape(tb[:bhi:mx]) }), capture(func() []any { return bshape(iastprop.BytesSliceFullZero(tb, bhi, mx)) }))
			check("BytesSliceAll", capture(func() []any { return bshape(tb[:]) }), capture(func() []any { return bshape(iastprop.BytesSliceAll(tb)) }))
			var nilb []byte
			check("BytesSliceNil", capture(func() []any { return []any{nilb[:], nilb[0:0] == nil} }), capture(func() []any { return []any{iastprop.BytesSliceAll(nilb), iastprop.BytesSliceBounds(nilb, 0, 0) == nil} }))
			check("BytesToString", capture(func() []any { return []any{string(tb), string(tb[:0]), string(nilb)} }),
				capture(func() []any {
					return []any{iastprop.BytesToString(tb), iastprop.BytesToString(tb[:0]), iastprop.BytesToString(nilb)}
				}))
			check("BytesToStringNamed", capture(func() []any { return []any{string(namedBytes(tb))} }), capture(func() []any { return []any{iastprop.BytesToString(namedBytes(tb))} }))
			// Mutating the source bytes after conversion must not affect the string (copy semantics).
			if len(tb) > 0 {
				conv := iastprop.BytesToString(tb)
				before := strings.Clone(conv)
				tb[0] ^= 0xff
				if conv != before {
					t.Errorf("BytesToString result aliases mutable bytes")
				}
				tb[0] ^= 0xff
			}
		}
		env.finish()
	}
	t.Logf("operators: taintedInputs=%d divergences=%d", tainted, divergences)
	if tainted == 0 {
		t.Errorf("harness sanity: no tainted operator inputs")
	}
}
