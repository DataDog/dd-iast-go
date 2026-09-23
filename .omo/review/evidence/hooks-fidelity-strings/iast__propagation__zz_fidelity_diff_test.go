// Differential fidelity harness (review node hooks-fidelity-strings).
// Calls every iast/propagation strings/fmt/strconv/url/operator wrapper
// directly and the uninstrumented stdlib/native operation with identical
// inputs, under several taint modes, and asserts identical results, identical
// panics, identical callback side effects, and no unexpected allocations.

package propagation_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unsafe"

	iastprop "github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

// ---------------------------------------------------------------------------
// outcome capture

type outcome struct {
	vals     []any
	panicked bool
	pval     any
	ptype    string
	pstr     string
}

func capture(f func() []any) (o outcome) {
	defer func() {
		if r := recover(); r != nil {
			o.panicked = true
			o.pval = r
			o.ptype = fmt.Sprintf("%T", r)
			o.pstr = fmt.Sprint(r)
		}
	}()
	o.vals = f()
	return o
}

func sameErr(a, b error) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if reflect.TypeOf(a) != reflect.TypeOf(b) {
		return false
	}
	if reflect.TypeOf(a).Comparable() && a != b {
		// sentinel identity must hold for comparable errors
		if !reflect.DeepEqual(a, b) {
			return false
		}
	}
	return a.Error() == b.Error() && (errors.Is(a, b) || reflect.DeepEqual(a, b))
}

func sameOutcome(a, b outcome) (bool, string) {
	if a.panicked != b.panicked {
		return false, fmt.Sprintf("panic mismatch std=%v(%s %q) wrap=%v(%s %q)", a.panicked, a.ptype, a.pstr, b.panicked, b.ptype, b.pstr)
	}
	if a.panicked {
		if a.ptype != b.ptype || a.pstr != b.pstr {
			return false, fmt.Sprintf("panic value mismatch std=(%s %q) wrap=(%s %q)", a.ptype, a.pstr, b.ptype, b.pstr)
		}
		if ae, ok := a.pval.(error); ok {
			be, _ := b.pval.(error)
			if !sameErr(ae, be) {
				return false, fmt.Sprintf("panic error mismatch %#v vs %#v", a.pval, b.pval)
			}
		} else if reflect.TypeOf(a.pval).Comparable() && a.pval != b.pval {
			return false, fmt.Sprintf("panic value != std=%#v wrap=%#v", a.pval, b.pval)
		}
		return true, ""
	}
	if len(a.vals) != len(b.vals) {
		return false, "arity mismatch"
	}
	for i := range a.vals {
		av, bv := a.vals[i], b.vals[i]
		ae, aIsErr := av.(error)
		be, bIsErr := bv.(error)
		if aIsErr || bIsErr || (av == nil) != (bv == nil) {
			if !sameErr(ae, be) {
				return false, fmt.Sprintf("result[%d] error mismatch std=%#v wrap=%#v", i, av, bv)
			}
			continue
		}
		if !reflect.DeepEqual(av, bv) {
			return false, fmt.Sprintf("result[%d] mismatch std=%#v wrap=%#v", i, av, bv)
		}
		// nil-vs-empty slice identity is observable (s == nil)
		if as, ok := av.([]string); ok {
			bs := bv.([]string)
			if (as == nil) != (bs == nil) || len(as) != len(bs) || cap(as) != cap(bs) {
				return false, fmt.Sprintf("result[%d] slice header mismatch nil=%v/%v len=%d/%d cap=%d/%d", i, as == nil, bs == nil, len(as), len(bs), cap(as), cap(bs))
			}
		}
		if ab, ok := av.([]byte); ok {
			bb := bv.([]byte)
			if (ab == nil) != (bb == nil) || len(ab) != len(bb) || cap(ab) != cap(bb) {
				return false, fmt.Sprintf("result[%d] byte slice header mismatch", i)
			}
		}
	}
	return true, ""
}

// ---------------------------------------------------------------------------
// taint modes

func enableIAST(t testing.TB) {
	pe, ps, pm := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = pe, ps, pm
	})
}

var src = taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "p"}

type mode int

const (
	modeInactive      mode = iota // no request scope at all
	modeActiveClean               // active owner, untainted inputs
	modeTainted                   // active owner, every input tainted
	modeTaintedWindow             // active owner, inputs are tainted interior windows
	modeStale                     // inputs tainted by a finished owner
	modeOtherOwner                // tainted by owner A (finished), owner B active
	modeCount
)

func (m mode) String() string {
	return [...]string{"inactive", "active-clean", "tainted", "tainted-window", "stale", "other-owner"}[m]
}

// prepare returns content-equal inputs for mode m and a cleanup func.
func prepare(m mode, in []string) ([]string, func()) {
	out := make([]string, len(in))
	copy(out, in)
	switch m {
	case modeInactive:
		return out, func() {}
	case modeActiveClean:
		_, scope, _ := request.Begin(context.Background())
		return out, scope.Finish
	case modeTainted, modeTaintedWindow:
		ctx, scope, _ := request.Begin(context.Background())
		for i, s := range in {
			if m == modeTaintedWindow {
				big := taint.TaintString(ctx, src, "<<"+s+">>")
				out[i] = iastprop.StringSliceBounds(big, 2, 2+len(s))
			} else {
				out[i] = taint.TaintString(ctx, src, s)
			}
		}
		return out, scope.Finish
	case modeStale:
		ctx, scope, _ := request.Begin(context.Background())
		for i, s := range in {
			out[i] = taint.TaintString(ctx, src, s)
		}
		scope.Finish()
		return out, func() {}
	case modeOtherOwner:
		ctx, scopeA, _ := request.Begin(context.Background())
		for i, s := range in {
			out[i] = taint.TaintString(ctx, src, s)
		}
		scopeA.Finish()
		_, scopeB, _ := request.Begin(context.Background())
		return out, scopeB.Finish
	}
	panic("bad mode")
}

// ---------------------------------------------------------------------------
// predicates / mappings (with call recording for side-effect comparison)

type rec struct{ calls []rune }

func predicate(n int, r *rec) func(rune) bool {
	base := [...]func(rune) bool{
		unicode.IsSpace,
		unicode.IsUpper,
		func(c rune) bool { return c == ',' || c == ';' },
		func(c rune) bool { return c == unicode.ReplacementChar },
		func(c rune) bool {
			if c == 'X' {
				panic(fmt.Errorf("predicate boom %q", c))
			}
			return c == ' '
		},
		func(rune) bool { return true },
		func(rune) bool { return false },
	}[uint(n)%7]
	return func(c rune) bool { r.calls = append(r.calls, c); return base(c) }
}

func mapping(n int, r *rec) func(rune) rune {
	base := [...]func(rune) rune{
		unicode.ToUpper,
		func(c rune) rune {
			if c == ' ' {
				return -1
			}
			return c
		},
		func(c rune) rune { return c },
		func(c rune) rune {
			if c == 'X' {
				panic("mapping boom")
			}
			return c + 1
		},
		func(rune) rune { return 0xD800 }, // invalid surrogate
		func(c rune) rune {
			if c < 0x80 {
				return 0x10FFFF
			}
			return 'a'
		},
	}[uint(n)%6]
	return func(c rune) rune { r.calls = append(r.calls, c); return base(c) }
}

// ---------------------------------------------------------------------------
// string ops

type op struct {
	name string
	nstr int
	call func(w bool, s []string, n int) []any
}

func collectN(seq func(func(string) bool), limit int) []string {
	var out []string
	seq(func(v string) bool {
		out = append(out, v)
		return limit <= 0 || len(out) < limit
	})
	return out
}

func seqOp(name string, nstr int, std, wrap func(s []string, n int) func(func(string) bool)) op {
	return op{name, nstr, func(w bool, s []string, n int) []any {
		f := std
		if w {
			f = wrap
		}
		seq := f(s, n)
		full := collectN(seq, 0)
		early := collectN(seq, n%4+1) // exercise early break
		again := collectN(seq, 0)     // sequences must be re-iterable
		return []any{full, early, again}
	}}
}

func predOp(name string, std, wrap func(string, func(rune) bool) any) op {
	return op{name, 1, func(w bool, s []string, n int) []any {
		var r rec
		p := predicate(n, &r)
		var res any
		if w {
			res = wrap(s[0], p)
		} else {
			res = std(s[0], p)
		}
		return []any{res, r.calls}
	}}
}

func pick[T any](w bool, a, b T) T {
	if w {
		return b
	}
	return a
}

var stringOps = []op{
	{"Clone", 1, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strings.Clone, iastprop.StringsClone)(s[0])}
	}},
	{"Cut", 2, func(w bool, s []string, _ int) []any {
		a, b, f := pick(w, strings.Cut, iastprop.StringsCut)(s[0], s[1])
		return []any{a, b, f}
	}},
	{"CutPrefix", 2, func(w bool, s []string, _ int) []any {
		a, f := pick(w, strings.CutPrefix, iastprop.StringsCutPrefix)(s[0], s[1])
		return []any{a, f}
	}},
	{"CutSuffix", 2, func(w bool, s []string, _ int) []any {
		a, f := pick(w, strings.CutSuffix, iastprop.StringsCutSuffix)(s[0], s[1])
		return []any{a, f}
	}},
	{"Split", 2, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strings.Split, iastprop.StringsSplit)(s[0], s[1])}
	}},
	{"SplitN", 2, func(w bool, s []string, n int) []any {
		return []any{pick(w, strings.SplitN, iastprop.StringsSplitN)(s[0], s[1], n)}
	}},
	{"SplitAfter", 2, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strings.SplitAfter, iastprop.StringsSplitAfter)(s[0], s[1])}
	}},
	{"SplitAfterN", 2, func(w bool, s []string, n int) []any {
		return []any{pick(w, strings.SplitAfterN, iastprop.StringsSplitAfterN)(s[0], s[1], n)}
	}},
	seqOp("SplitSeq", 2,
		func(s []string, _ int) func(func(string) bool) { return strings.SplitSeq(s[0], s[1]) },
		func(s []string, _ int) func(func(string) bool) { return iastprop.StringsSplitSeq(s[0], s[1]) }),
	seqOp("SplitAfterSeq", 2,
		func(s []string, _ int) func(func(string) bool) { return strings.SplitAfterSeq(s[0], s[1]) },
		func(s []string, _ int) func(func(string) bool) { return iastprop.StringsSplitAfterSeq(s[0], s[1]) }),
	seqOp("Lines", 1,
		func(s []string, _ int) func(func(string) bool) { return strings.Lines(s[0]) },
		func(s []string, _ int) func(func(string) bool) { return iastprop.StringsLines(s[0]) }),
	seqOp("FieldsSeq", 1,
		func(s []string, _ int) func(func(string) bool) { return strings.FieldsSeq(s[0]) },
		func(s []string, _ int) func(func(string) bool) { return iastprop.StringsFieldsSeq(s[0]) }),
	{"FieldsFuncSeq", 1, func(w bool, s []string, n int) []any {
		var r rec
		p := predicate(n, &r)
		var seq func(func(string) bool)
		if w {
			seq = iastprop.StringsFieldsFuncSeq(s[0], p)
		} else {
			seq = strings.FieldsFuncSeq(s[0], p)
		}
		full := collectN(seq, 0)
		early := collectN(seq, n%4+1)
		return []any{full, early, r.calls}
	}},
	{"Fields", 1, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strings.Fields, iastprop.StringsFields)(s[0])}
	}},
	predOp("FieldsFunc",
		func(v string, p func(rune) bool) any { return strings.FieldsFunc(v, p) },
		func(v string, p func(rune) bool) any { return iastprop.StringsFieldsFunc(v, p) }),
	{"Join", -1, func(w bool, s []string, _ int) []any {
		elems := s[1:]
		before := slices.Clone(elems)
		r := pick(w, strings.Join, iastprop.StringsJoin)(elems, s[0])
		return []any{r, slices.Equal(before, elems)}
	}},
	{"Repeat", 1, func(w bool, s []string, n int) []any {
		return []any{pick(w, strings.Repeat, iastprop.StringsRepeat)(s[0], n)}
	}},
	{"Replace", 3, func(w bool, s []string, n int) []any {
		return []any{pick(w, strings.Replace, iastprop.StringsReplace)(s[0], s[1], s[2], n)}
	}},
	{"ReplaceAll", 3, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strings.ReplaceAll, iastprop.StringsReplaceAll)(s[0], s[1], s[2])}
	}},
	{"Replacer", -1, func(w bool, s []string, _ int) []any {
		pairs := s[1:]
		if len(pairs)%2 == 1 {
			pairs = pairs[:len(pairs)-1]
		}
		r := strings.NewReplacer(pairs...)
		if w {
			return []any{iastprop.ReplacerReplace(r, s[0])}
		}
		return []any{r.Replace(s[0])}
	}},
	{"Trim", 2, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strings.Trim, iastprop.StringsTrim)(s[0], s[1])}
	}},
	{"TrimSpace", 1, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strings.TrimSpace, iastprop.StringsTrimSpace)(s[0])}
	}},
	{"TrimLeft", 2, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strings.TrimLeft, iastprop.StringsTrimLeft)(s[0], s[1])}
	}},
	{"TrimRight", 2, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strings.TrimRight, iastprop.StringsTrimRight)(s[0], s[1])}
	}},
	{"TrimPrefix", 2, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strings.TrimPrefix, iastprop.StringsTrimPrefix)(s[0], s[1])}
	}},
	{"TrimSuffix", 2, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strings.TrimSuffix, iastprop.StringsTrimSuffix)(s[0], s[1])}
	}},
	predOp("TrimFunc",
		func(v string, p func(rune) bool) any { return strings.TrimFunc(v, p) },
		func(v string, p func(rune) bool) any { return iastprop.StringsTrimFunc(v, p) }),
	predOp("TrimLeftFunc",
		func(v string, p func(rune) bool) any { return strings.TrimLeftFunc(v, p) },
		func(v string, p func(rune) bool) any { return iastprop.StringsTrimLeftFunc(v, p) }),
	predOp("TrimRightFunc",
		func(v string, p func(rune) bool) any { return strings.TrimRightFunc(v, p) },
		func(v string, p func(rune) bool) any { return iastprop.StringsTrimRightFunc(v, p) }),
	{"ToLower", 1, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strings.ToLower, iastprop.StringsToLower)(s[0])}
	}},
	{"ToUpper", 1, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strings.ToUpper, iastprop.StringsToUpper)(s[0])}
	}},
	{"ToTitle", 1, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strings.ToTitle, iastprop.StringsToTitle)(s[0])}
	}},
	{"Map", 1, func(w bool, s []string, n int) []any {
		var r rec
		m := mapping(n, &r)
		res := pick(w, strings.Map, iastprop.StringsMap)(m, s[0])
		return []any{res, r.calls}
	}},
	{"ToValidUTF8", 2, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strings.ToValidUTF8, iastprop.StringsToValidUTF8)(s[0], s[1])}
	}},
	{"QueryEscape", 1, func(w bool, s []string, _ int) []any {
		return []any{pick(w, url.QueryEscape, iastprop.URLQueryEscape)(s[0])}
	}},
	{"PathEscape", 1, func(w bool, s []string, _ int) []any {
		return []any{pick(w, url.PathEscape, iastprop.URLPathEscape)(s[0])}
	}},
	{"QueryUnescape", 1, func(w bool, s []string, _ int) []any {
		r, err := pick(w, url.QueryUnescape, iastprop.URLQueryUnescape)(s[0])
		return []any{r, err}
	}},
	{"PathUnescape", 1, func(w bool, s []string, _ int) []any {
		r, err := pick(w, url.PathUnescape, iastprop.URLPathUnescape)(s[0])
		return []any{r, err}
	}},
	{"Quote", 1, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strconv.Quote, iastprop.StrconvQuote)(s[0])}
	}},
	{"QuoteToASCII", 1, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strconv.QuoteToASCII, iastprop.StrconvQuoteToASCII)(s[0])}
	}},
	{"QuoteToGraphic", 1, func(w bool, s []string, _ int) []any {
		return []any{pick(w, strconv.QuoteToGraphic, iastprop.StrconvQuoteToGraphic)(s[0])}
	}},
	{"Unquote", 1, func(w bool, s []string, _ int) []any {
		r, err := pick(w, strconv.Unquote, iastprop.StrconvUnquote)(s[0])
		return []any{r, err}
	}},
}

// ---------------------------------------------------------------------------
// fmt ops

type myStr string
type myBytes []byte
type myByte uint8
type myByteSlice []myByte

var fmtCalls int

type counter struct {
	v    string
	boom bool
}

func (c counter) String() string {
	fmtCalls++
	if c.boom {
		panic("stringer boom")
	}
	return c.v
}

type nilStringer struct{ v string }

func (p *nilStringer) String() string { return p.v } // panics on nil receiver

type fmtErr struct{ v string }

func (e fmtErr) Error() string { return e.v }

type formatterT struct{}

func (f formatterT) Format(st fmt.State, verb rune) { fmtCalls++; fmt.Fprintf(st, "F<%c>", verb) }

type gostr struct{}

func (g gostr) GoString() string { fmtCalls++; return "GS" }

func fmtArgs(r *rand.Rand, s []string) []any {
	k := r.IntN(20) // cross the 15/16 inspected-argument limits
	args := make([]any, 0, k)
	for i := 0; i < k; i++ {
		v := s[i%len(s)]
		switch r.IntN(18) {
		case 0, 1:
			args = append(args, v)
		case 2:
			args = append(args, []byte(v))
		case 3:
			args = append(args, myStr(v))
		case 4:
			args = append(args, myBytes(v))
		case 5:
			args = append(args, myByteSlice(v))
		case 6:
			args = append(args, counter{v: v})
		case 7:
			args = append(args, counter{v: v, boom: true})
		case 8:
			args = append(args, nil)
		case 9:
			args = append(args, r.IntN(1000)-500)
		case 10:
			args = append(args, (*nilStringer)(nil))
		case 11:
			args = append(args, fmtErr{v})
		case 12:
			args = append(args, formatterT{})
		case 13:
			args = append(args, gostr{})
		case 14:
			args = append(args, []string{v, v})
		case 15:
			args = append(args, [2]string{v, "k"})
		case 16:
			args = append(args, reflect.ValueOf(v))
		case 17:
			args = append(args, []byte(nil))
		}
	}
	return args
}

var formats = []string{
	"", "%", "%!", "%s", "%v", "%q", "%x", "%X % x", "%d", "%#v", "%T", "%+v|%-8s|%8.3q",
	"%[2]s %[1]s", "%[5]v", "%*d", "%.*s", "%s %s %s %s", "%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v%v",
	"%c %U", "%%", "%!(EXTRA)", "\xff%s\xfe", "%[0]d", "%[-1]d", "%9999999999999999999d", "%.9999999999d",
}

// ---------------------------------------------------------------------------
// input generation

var alphabet = []string{
	"a", "b", "X", " ", "\t", "\n", "\r\n", ",", ";", "%", "%2", "%zz", "%41", "+", "/", "\"", "\\", "'", "`",
	"é", "İ", "ß", "ǅ", "ﬀ", "Σ", "\u2028", "\u00a0", "\u0085", "日本", "\xff", "\xc3", "\xed\xa0\x80", "\x00",
	"\U0001F600", "\uFFFD", "ab", "abc",
}

func genString(r *rand.Rand) string {
	var b strings.Builder
	switch r.IntN(20) {
	case 0:
		return ""
	case 1:
		return alphabet[r.IntN(len(alphabet))]
	case 2: // long, crosses MaxRootBytes (64 KiB) sometimes
		n := r.IntN(70000)
		for b.Len() < n {
			b.WriteString(alphabet[r.IntN(len(alphabet))])
		}
		return b.String()
	case 3: // many separators, > 32 windows
		for i := 0; i < 40+r.IntN(40); i++ {
			b.WriteString("ab,")
		}
		return b.String()
	}
	n := r.IntN(12)
	for i := 0; i < n; i++ {
		b.WriteString(alphabet[r.IntN(len(alphabet))])
	}
	if r.IntN(6) == 0 {
		return strconv.Quote(b.String())
	}
	return b.String()
}

var counts = []int{
	math.MinInt, -100, -2, -1, 0, 1, 2, 3, 5, 31, 32, 33, 40, 1 << 20, math.MaxInt, math.MaxInt / 2,
}

func genCount(r *rand.Rand) int {
	if r.IntN(3) == 0 {
		return r.IntN(10) - 2
	}
	return counts[r.IntN(len(counts))]
}

// Repeat with a huge count and non-empty input would allocate terabytes; the
// stdlib only panics for lengths overflowing int. Keep counts that either fit
// in a small result or overflow.
func safeRepeatCount(s string, n int) int {
	if n <= 0 || len(s) == 0 {
		return n
	}
	if len(s) > math.MaxInt/n {
		return n // overflow panic path
	}
	if len(s)*n > 200000 {
		return 200000/len(s) + 1
	}
	return n
}

// ---------------------------------------------------------------------------
// driver

type failure struct {
	op, mode, detail string
	inputs           []string
	n                int
}

func quoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		if len(s) > 80 {
			out[i] = fmt.Sprintf("%q...(len=%d)", s[:80], len(s))
		} else {
			out[i] = strconv.Quote(s)
		}
	}
	return out
}

func runOp(o op, m mode, in []string, n int) (ok bool, detail string) {
	if o.name == "Repeat" {
		n = safeRepeatCount(in[0], n)
	}
	std := capture(func() []any { return o.call(false, in, n) })
	args, cleanup := prepare(m, in)
	defer cleanup()
	wr := capture(func() []any { return o.call(true, args, n) })
	// stdlib on the exact same (possibly tainted) input objects too
	std2 := capture(func() []any { return o.call(false, args, n) })
	if ok, d := sameOutcome(std, wr); !ok {
		return false, d
	}
	if ok, d := sameOutcome(std2, wr); !ok {
		return false, "vs std on same objects: " + d
	}
	return true, ""
}

func TestFidelityDifferentialStrings(t *testing.T) {
	enableIAST(t)
	r := rand.New(rand.NewPCG(0xdd1a57, 0x60))
	iterations := 1500
	if testing.Short() {
		iterations = 150
	}
	var failures []failure
	total := 0
	for _, o := range stringOps {
		for m := mode(0); m < modeCount; m++ {
			// deterministic edge table
			edge := [][]string{
				{"", "", "", ""}, {"a", "", "b", ""}, {"ab", "ab", "ab", "ab"}, {"\xff\xfe", "\xff", "?", "\xff"},
				{"İİ", "i", "I", "İ"}, {"a,b,c", ",", ";", ","}, {"  x  ", " ", "", " "}, {"%zz%4", "%", "", "%"},
				{"\"a\\tb\"", "\"", "'", "`x`"}, {strings.Repeat("ab,", 50), ",", "--", ","}, {"'a'", "a", "a", "a"},
			}
			for _, e := range edge {
				for _, n := range counts {
					in := buildInputs(o, e, r)
					total++
					if ok, d := runOp(o, m, in, n); !ok {
						failures = append(failures, failure{o.name, m.String(), d, in, n})
					}
				}
			}
			for i := 0; i < iterations; i++ {
				in := buildInputs(o, nil, r)
				n := genCount(r)
				total++
				if ok, d := runOp(o, m, in, n); !ok {
					failures = append(failures, failure{o.name, m.String(), d, in, n})
				}
			}
		}
	}
	t.Logf("string ops: %d ops x %d modes, %d differential cases", len(stringOps), modeCount, total)
	reportFailures(t, failures)
}

func buildInputs(o op, edge []string, r *rand.Rand) []string {
	k := o.nstr
	if k < 0 { // variadic: separator + elements (cross 16/17 element limits)
		k = 1 + r.IntN(20)
	}
	in := make([]string, k)
	for i := range in {
		if edge != nil {
			in[i] = edge[i%len(edge)]
		} else {
			in[i] = genString(r)
		}
	}
	return in
}

func reportFailures(t *testing.T, failures []failure) {
	t.Helper()
	seen := map[string]int{}
	for _, f := range failures {
		key := f.op + "/" + f.mode
		seen[key]++
		if seen[key] <= 3 {
			t.Errorf("DIVERGENCE %s [%s] n=%d inputs=%v: %s", f.op, f.mode, f.n, quoteAll(f.inputs), f.detail)
		}
	}
	if len(failures) > 0 {
		t.Errorf("%d divergences total (%d op/mode groups)", len(failures), len(seen))
	}
}

func TestFidelityDifferentialFmt(t *testing.T) {
	enableIAST(t)
	r := rand.New(rand.NewPCG(0xf417, 0x5))
	iterations := 1000
	if testing.Short() {
		iterations = 300
	}
	var failures []failure
	total := 0
	for m := mode(0); m < modeCount; m++ {
		for i := 0; i < iterations; i++ {
			in := []string{genString(r), genString(r), genString(r), formats[r.IntN(len(formats))]}
			if r.IntN(4) == 0 {
				in[3] = genString(r)
			}
			seed := r.Uint64()
			for _, which := range []string{"Sprint", "Sprintf", "Sprintln"} {
				call := func(w bool, s []string) []any {
					fmtCalls = 0
					rr := rand.New(rand.NewPCG(seed, 1))
					args := fmtArgs(rr, s[:3])
					before := fmt.Sprintf("%#v", args)
					var res string
					switch which {
					case "Sprint":
						res = pick(w, fmt.Sprint, iastprop.FmtSprint)(args...)
					case "Sprintln":
						res = pick(w, fmt.Sprintln, iastprop.FmtSprintln)(args...)
					default:
						res = pick(w, fmt.Sprintf, iastprop.FmtSprintf)(s[3], args...)
					}
					after := fmt.Sprintf("%#v", args)
					// The harness allocates a fresh call counter per invocation and some
					// argument kinds print its address; normalize heap addresses only.
					calls := fmtCalls
					return []any{res, calls, ptrRE.ReplaceAllString(before, "") == ptrRE.ReplaceAllString(after, "")}
				}
				total++
				std := capture(func() []any { return call(false, in) })
				args, cleanup := prepare(m, in)
				wr := capture(func() []any { return call(true, args) })
				std2 := capture(func() []any { return call(false, args) })
				cleanup()
				// %p / pointer-bearing output differs across distinct objects; compare
				// only against std on the same objects when pointers are printed.
				if ok, d := sameOutcome(std2, wr); !ok {
					failures = append(failures, failure{which, m.String(), d, in, 0})
				} else if ok, d := sameOutcome(std, wr); !ok && !pointery(std, wr) {
					failures = append(failures, failure{which, m.String(), "vs fresh std: " + d, in, 0})
				}
			}
		}
	}
	t.Logf("fmt: %d differential cases", total)
	reportFailures(t, failures)
}

var ptrRE = regexp.MustCompile(`0x[0-9a-f]{8,}`)

func pointery(a, b outcome) bool {
	for _, o := range []outcome{a, b} {
		if len(o.vals) > 0 {
			if s, ok := o.vals[0].(string); ok && strings.Contains(s, "0x1") {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// operators

type named string
type namedBytes []byte

func TestFidelityDifferentialConcat(t *testing.T) {
	enableIAST(t)
	r := rand.New(rand.NewPCG(0xc0, 0x11))
	var failures []failure
	for m := mode(0); m < modeCount; m++ {
		for i := 0; i < 3000; i++ {
			k := 2 + r.IntN(15)
			in := make([]string, k)
			for j := range in {
				if r.IntN(3) == 0 {
					in[j] = ""
				} else {
					in[j] = genString(r)
				}
			}
			std := strings.Join(in, "")
			args, cleanup := prepare(m, in)
			got := concatN(args)
			gotNamed := string(concatNNamed(args))
			cleanup()
			if got != std || gotNamed != std {
				failures = append(failures, failure{fmt.Sprintf("Concat%d", k), m.String(), "result mismatch", in, 0})
			}
		}
	}
	reportFailures(t, failures)
}

func concatN(s []string) string {
	switch len(s) {
	case 2:
		return iastprop.Concat2(s[0], s[1])
	case 3:
		return iastprop.Concat3(s[0], s[1], s[2])
	case 4:
		return iastprop.Concat4(s[0], s[1], s[2], s[3])
	case 5:
		return iastprop.Concat5(s[0], s[1], s[2], s[3], s[4])
	case 6:
		return iastprop.Concat6(s[0], s[1], s[2], s[3], s[4], s[5])
	case 7:
		return iastprop.Concat7(s[0], s[1], s[2], s[3], s[4], s[5], s[6])
	case 8:
		return iastprop.Concat8(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7])
	case 9:
		return iastprop.Concat9(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8])
	case 10:
		return iastprop.Concat10(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9])
	case 11:
		return iastprop.Concat11(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10])
	case 12:
		return iastprop.Concat12(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11])
	case 13:
		return iastprop.Concat13(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12])
	case 14:
		return iastprop.Concat14(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13])
	case 15:
		return iastprop.Concat15(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13], s[14])
	case 16:
		return iastprop.Concat16(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12], s[13], s[14], s[15])
	}
	panic("arity")
}

func concatNNamed(in []string) named {
	s := make([]named, len(in))
	for i := range in {
		s[i] = named(in[i])
	}
	switch len(s) {
	case 2:
		return iastprop.Concat2(s[0], s[1])
	case 3:
		return iastprop.Concat3(s[0], s[1], s[2])
	default:
		return named(concatN(in))
	}
}

// native slice references, written without generics so the compiler emits the
// same bounds checks customer code would get.
func nStrLowInt(v string, l int) string                      { return v[l:] }
func nStrHighInt(v string, h int) string                     { return v[:h] }
func nStrBoundsInt(v string, l, h int) string                { return v[l:h] }
func nStrBoundsU8(v string, l, h uint8) string               { return v[l:h] }
func nStrBoundsI8(v string, l, h int8) string                { return v[l:h] }
func nStrBoundsU64(v string, l, h uint64) string             { return v[l:h] }
func nStrBoundsUptr(v string, l, h uintptr) string           { return v[l:h] }
func nStrBoundsI64(v string, l, h int64) string              { return v[l:h] }
func nBytesFullInt(v []byte, l, h, m int) []byte             { return v[l:h:m] }
func nBytesFullU64(v []byte, l, h, m uint64) []byte          { return v[l:h:m] }
func nBytesFullZeroInt(v []byte, h, m int) []byte            { return v[:h:m] }
func nBytesBoundsInt(v []byte, l, h int) []byte              { return v[l:h] }
func nBytesBoundsI8(v []byte, l, h int8) []byte              { return v[l:h] }
func nBytesLowInt(v []byte, l int) []byte                    { return v[l:] }
func nBytesHighU32(v []byte, h uint32) []byte                { return v[:h] }
func nBytesAll(v []byte) []byte                              { return v[:] }
func nNamedBoundsInt(v named, l, h int) named                { return v[l:h] }
func nNamedBytesBoundsInt(v namedBytes, l, h int) namedBytes { return v[l:h] }

func sliceHdr(b []byte) []any {
	return []any{string(b), len(b), cap(b), b == nil, uintptr(unsafe.Pointer(unsafe.SliceData(b)))}
}

func TestFidelityDifferentialSlicing(t *testing.T) {
	enableIAST(t)
	r := rand.New(rand.NewPCG(0x51, 0xce))
	var failures []failure
	idx := []int{-1 << 40, -129, -128, -1, 0, 1, 2, 3, 5, 7, 8, 16, 127, 128, 255, 256, 1 << 32, math.MaxInt}
	for m := mode(0); m < modeCount; m++ {
		for i := 0; i < 4000; i++ {
			v := genString(r)
			if len(v) > 300 {
				v = v[:300]
			}
			l, h, x := idx[r.IntN(len(idx))], idx[r.IntN(len(idx))], idx[r.IntN(len(idx))]
			if r.IntN(2) == 0 && len(v) > 0 {
				l, h, x = r.IntN(len(v)+2)-1, r.IntN(len(v)+2), r.IntN(len(v)+3)
			}
			args, cleanup := prepare(m, []string{v})
			sv := args[0]
			bv := []byte(sv)
			finishBytes := func() {}
			if m >= modeTainted {
				// taint bytes too, same content
				ctx, sc, _ := request.Begin(context.Background())
				bv = taint.TaintBytes(ctx, src, []byte(v))
				if m == modeStale || m == modeOtherOwner {
					sc.Finish()
				} else {
					finishBytes = sc.Finish
				}
			}
			type pair struct {
				name      string
				std, wrap func() []any
			}
			pairs := []pair{
				{"StrLow/int", func() []any { return []any{nStrLowInt(sv, l)} }, func() []any { return []any{iastprop.StringSliceLow(sv, l)} }},
				{"StrHigh/int", func() []any { return []any{nStrHighInt(sv, h)} }, func() []any { return []any{iastprop.StringSliceHigh(sv, h)} }},
				{"StrAll", func() []any { return []any{sv[:]} }, func() []any { return []any{iastprop.StringSliceAll(sv)} }},
				{"StrBounds/int", func() []any { return []any{nStrBoundsInt(sv, l, h)} }, func() []any { return []any{iastprop.StringSliceBounds(sv, l, h)} }},
				{"StrBounds/uint8", func() []any { return []any{nStrBoundsU8(sv, uint8(l), uint8(h))} }, func() []any { return []any{iastprop.StringSliceBounds(sv, uint8(l), uint8(h))} }},
				{"StrBounds/int8", func() []any { return []any{nStrBoundsI8(sv, int8(l), int8(h))} }, func() []any { return []any{iastprop.StringSliceBounds(sv, int8(l), int8(h))} }},
				{"StrBounds/uint64", func() []any { return []any{nStrBoundsU64(sv, uint64(l), uint64(h))} }, func() []any { return []any{iastprop.StringSliceBounds(sv, uint64(l), uint64(h))} }},
				{"StrBounds/uintptr", func() []any { return []any{nStrBoundsUptr(sv, uintptr(l), uintptr(h))} }, func() []any { return []any{iastprop.StringSliceBounds(sv, uintptr(l), uintptr(h))} }},
				{"StrBounds/int64", func() []any { return []any{nStrBoundsI64(sv, int64(l), int64(h))} }, func() []any { return []any{iastprop.StringSliceBounds(sv, int64(l), int64(h))} }},
				{"StrBounds/mixed", func() []any { return []any{sv[int8(l):uint64(h)]} }, func() []any { return []any{iastprop.StringSliceBounds(sv, int8(l), uint64(h))} }},
				{"NamedStrBounds", func() []any { return []any{nNamedBoundsInt(named(sv), l, h)} }, func() []any { return []any{iastprop.StringSliceBounds(named(sv), l, h)} }},
				{"BytesAll", func() []any { return sliceHdr(nBytesAll(bv)) }, func() []any { return sliceHdr(iastprop.BytesSliceAll(bv)) }},
				{"BytesLow/int", func() []any { return sliceHdr(nBytesLowInt(bv, l)) }, func() []any { return sliceHdr(iastprop.BytesSliceLow(bv, l)) }},
				{"BytesHigh/uint32", func() []any { return sliceHdr(nBytesHighU32(bv, uint32(h))) }, func() []any { return sliceHdr(iastprop.BytesSliceHigh(bv, uint32(h))) }},
				{"BytesBounds/int", func() []any { return sliceHdr(nBytesBoundsInt(bv, l, h)) }, func() []any { return sliceHdr(iastprop.BytesSliceBounds(bv, l, h)) }},
				{"BytesBounds/int8", func() []any { return sliceHdr(nBytesBoundsI8(bv, int8(l), int8(h))) }, func() []any { return sliceHdr(iastprop.BytesSliceBounds(bv, int8(l), int8(h))) }},
				{"BytesFull/int", func() []any { return sliceHdr(nBytesFullInt(bv, l, h, x)) }, func() []any { return sliceHdr(iastprop.BytesSliceFull(bv, l, h, x)) }},
				{"BytesFull/uint64", func() []any { return sliceHdr(nBytesFullU64(bv, uint64(l), uint64(h), uint64(x))) }, func() []any { return sliceHdr(iastprop.BytesSliceFull(bv, uint64(l), uint64(h), uint64(x))) }},
				{"BytesFullZero/int", func() []any { return sliceHdr(nBytesFullZeroInt(bv, h, x)) }, func() []any { return sliceHdr(iastprop.BytesSliceFullZero(bv, h, x)) }},
				{"NamedBytesBounds", func() []any { return sliceHdr(nNamedBytesBoundsInt(namedBytes(bv), l, h)) }, func() []any { return sliceHdr(iastprop.BytesSliceBounds(namedBytes(bv), l, h)) }},
				{"NilBytesAll", func() []any { return sliceHdr(nBytesAll(nil)) }, func() []any { return sliceHdr(iastprop.BytesSliceAll([]byte(nil))) }},
				{"BytesToString", func() []any { return []any{string(bv)} }, func() []any { return []any{iastprop.BytesToString(bv)} }},
				{"NamedBytesToString", func() []any { return []any{string(namedBytes(bv))} }, func() []any { return []any{iastprop.BytesToString(namedBytes(bv))} }},
			}
			for _, p := range pairs {
				a, b := capture(p.std), capture(p.wrap)
				if ok, d := sameOutcome(a, b); !ok {
					failures = append(failures, failure{p.name, m.String(), fmt.Sprintf("%s l=%d h=%d m=%d", d, l, h, x), []string{v}, 0})
				}
			}
			finishBytes()
			cleanup()
		}
	}
	reportFailures(t, failures)
}

// ---------------------------------------------------------------------------
// allocation fidelity on the inactive and active-but-clean paths

func TestFidelityAllocations(t *testing.T) {
	enableIAST(t)
	pred := unicode.IsSpace
	mp := unicode.ToUpper
	rep := strings.NewReplacer("a", "b")
	in := "  Alpha,Beta,Gamma  "
	elems := []string{"alpha", "beta"}
	type pair struct {
		name      string
		std, wrap func()
	}
	var sinkS string
	var sinkSS []string
	var sinkB bool
	var sinkE error
	pairs := []pair{
		{"Clone", func() { sinkS = strings.Clone(in) }, func() { sinkS = iastprop.StringsClone(in) }},
		{"Cut", func() { sinkS, _, sinkB = strings.Cut(in, ",") }, func() { sinkS, _, sinkB = iastprop.StringsCut(in, ",") }},
		{"Split", func() { sinkSS = strings.Split(in, ",") }, func() { sinkSS = iastprop.StringsSplit(in, ",") }},
		{"SplitSeq", func() {
			for v := range strings.SplitSeq(in, ",") {
				sinkS = v
			}
		}, func() {
			for v := range iastprop.StringsSplitSeq(in, ",") {
				sinkS = v
			}
		}},
		{"Lines", func() {
			for v := range strings.Lines(in) {
				sinkS = v
			}
		}, func() {
			for v := range iastprop.StringsLines(in) {
				sinkS = v
			}
		}},
		{"FieldsSeq", func() {
			for v := range strings.FieldsSeq(in) {
				sinkS = v
			}
		}, func() {
			for v := range iastprop.StringsFieldsSeq(in) {
				sinkS = v
			}
		}},
		{"FieldsFuncSeq", func() {
			for v := range strings.FieldsFuncSeq(in, pred) {
				sinkS = v
			}
		}, func() {
			for v := range iastprop.StringsFieldsFuncSeq(in, pred) {
				sinkS = v
			}
		}},
		{"Fields", func() { sinkSS = strings.Fields(in) }, func() { sinkSS = iastprop.StringsFields(in) }},
		{"Join", func() { sinkS = strings.Join(elems, "-") }, func() { sinkS = iastprop.StringsJoin(elems, "-") }},
		{"Repeat", func() { sinkS = strings.Repeat(in, 3) }, func() { sinkS = iastprop.StringsRepeat(in, 3) }},
		{"Replace", func() { sinkS = strings.Replace(in, "a", "b", -1) }, func() { sinkS = iastprop.StringsReplace(in, "a", "b", -1) }},
		{"Replacer", func() { sinkS = rep.Replace(in) }, func() { sinkS = iastprop.ReplacerReplace(rep, in) }},
		{"TrimFunc", func() { sinkS = strings.TrimFunc(in, pred) }, func() { sinkS = iastprop.StringsTrimFunc(in, pred) }},
		{"ToLower", func() { sinkS = strings.ToLower(in) }, func() { sinkS = iastprop.StringsToLower(in) }},
		{"Map", func() { sinkS = strings.Map(mp, in) }, func() { sinkS = iastprop.StringsMap(mp, in) }},
		{"ToValidUTF8", func() { sinkS = strings.ToValidUTF8(in, "?") }, func() { sinkS = iastprop.StringsToValidUTF8(in, "?") }},
		{"Sprint", func() { sinkS = fmt.Sprint(in, elems[0]) }, func() { sinkS = iastprop.FmtSprint(in, elems[0]) }},
		{"Sprintf", func() { sinkS = fmt.Sprintf("%s=%s", in, elems[0]) }, func() { sinkS = iastprop.FmtSprintf("%s=%s", in, elems[0]) }},
		{"Sprintln", func() { sinkS = fmt.Sprintln(in) }, func() { sinkS = iastprop.FmtSprintln(in) }},
		{"QueryEscape", func() { sinkS = url.QueryEscape(in) }, func() { sinkS = iastprop.URLQueryEscape(in) }},
		{"QueryUnescape", func() { sinkS, sinkE = url.QueryUnescape(in) }, func() { sinkS, sinkE = iastprop.URLQueryUnescape(in) }},
		{"Quote", func() { sinkS = strconv.Quote(in) }, func() { sinkS = iastprop.StrconvQuote(in) }},
		{"Unquote", func() { sinkS, sinkE = strconv.Unquote(`"` + in + `"`) }, func() { sinkS, sinkE = iastprop.StrconvUnquote(`"` + in + `"`) }},
	}
	for _, m := range []mode{modeInactive, modeActiveClean} {
		_, cleanup := prepare(m, nil)
		for _, p := range pairs {
			a := testing.AllocsPerRun(200, p.std)
			b := testing.AllocsPerRun(200, p.wrap)
			if a != b {
				t.Logf("ALLOC-DIFF [%s] %-14s std=%.0f wrap=%.0f", m, p.name, a, b)
			}
		}
		cleanup()
	}
	_, _, _, _ = sinkS, sinkSS, sinkB, sinkE
}

// Result identity: stdlib functions that return their input (or a window of
// it) unchanged; record whether the wrapper preserves that aliasing.
func TestFidelityAliasIdentity(t *testing.T) {
	enableIAST(t)
	type pair struct {
		name      string
		in        string
		std, wrap func(string) string
	}
	pairs := []pair{
		{"Replace n=0", "hello", func(s string) string { return strings.Replace(s, "l", "L", 0) }, func(s string) string { return iastprop.StringsReplace(s, "l", "L", 0) }},
		{"ToLower unchanged", "hello", strings.ToLower, iastprop.StringsToLower},
		{"Map identity", "hello", func(s string) string { return strings.Map(func(r rune) rune { return r }, s) }, func(s string) string { return iastprop.StringsMap(func(r rune) rune { return r }, s) }},
		{"ToValidUTF8 valid", "hello", func(s string) string { return strings.ToValidUTF8(s, "?") }, func(s string) string { return iastprop.StringsToValidUTF8(s, "?") }},
		{"Repeat 1", "hello", func(s string) string { return strings.Repeat(s, 1) }, func(s string) string { return iastprop.StringsRepeat(s, 1) }},
		{"Join one", "hello", func(s string) string { return strings.Join([]string{s}, ",") }, func(s string) string { return iastprop.StringsJoin([]string{s}, ",") }},
		{"Concat empty", "hello", func(s string) string { e := ""; return e + s }, func(s string) string { return iastprop.Concat2("", s) }},
		{"Replacer nomatch", "hello", func(s string) string { return strings.NewReplacer("z", "y").Replace(s) }, func(s string) string { return iastprop.ReplacerReplace(strings.NewReplacer("z", "y"), s) }},
		{"Sprint single string", "hello", func(s string) string { return fmt.Sprint(s) }, func(s string) string { return iastprop.FmtSprint(s) }},
	}
	for _, m := range []mode{modeInactive, modeTainted, modeTaintedWindow} {
		for _, p := range pairs {
			args, cleanup := prepare(m, []string{p.in})
			v := args[0]
			a, b := p.std(v), p.wrap(v)
			sameA := unsafe.StringData(a) == unsafe.StringData(v)
			sameB := unsafe.StringData(b) == unsafe.StringData(v)
			if a != b || sameA != sameB {
				t.Logf("ALIAS-DIFF [%s] %-22s equal=%v stdAliasesInput=%v wrapAliasesInput=%v", m, p.name, a == b, sameA, sameB)
			}
			cleanup()
		}
	}
}

// nil *strings.Replacer and nil predicate panics must be identical.
func TestFidelityNilPanics(t *testing.T) {
	enableIAST(t)
	for _, m := range []mode{modeInactive, modeTainted} {
		args, cleanup := prepare(m, []string{"hello world"})
		v := args[0]
		cases := []struct {
			name      string
			std, wrap func() []any
		}{
			{"nil Replacer", func() []any { var r *strings.Replacer; return []any{r.Replace(v)} }, func() []any { return []any{iastprop.ReplacerReplace(nil, v)} }},
			{"nil TrimFunc pred", func() []any { return []any{strings.TrimFunc(v, nil)} }, func() []any { return []any{iastprop.StringsTrimFunc(v, nil)} }},
			{"nil FieldsFunc pred", func() []any { return []any{strings.FieldsFunc(v, nil)} }, func() []any { return []any{iastprop.StringsFieldsFunc(v, nil)} }},
			{"nil Map", func() []any { return []any{strings.Map(nil, v)} }, func() []any { return []any{iastprop.StringsMap(nil, v)} }},
			{"nil FieldsFuncSeq pred", func() []any { return []any{slices.Collect(strings.FieldsFuncSeq(v, nil))} }, func() []any { return []any{slices.Collect(iastprop.StringsFieldsFuncSeq(v, nil))} }},
			{"Repeat -1", func() []any { return []any{strings.Repeat(v, -1)} }, func() []any { return []any{iastprop.StringsRepeat(v, -1)} }},
			{"Repeat overflow", func() []any { return []any{strings.Repeat(v, math.MaxInt/2)} }, func() []any { return []any{iastprop.StringsRepeat(v, math.MaxInt/2)} }},
			{"Sprintf nil-receiver Stringer", func() []any { return []any{fmt.Sprintf("%s %s", (*nilStringer)(nil), v)} }, func() []any { return []any{iastprop.FmtSprintf("%s %s", (*nilStringer)(nil), v)} }},
		}
		for _, c := range cases {
			a, b := capture(c.std), capture(c.wrap)
			if ok, d := sameOutcome(a, b); !ok {
				t.Errorf("DIVERGENCE [%s] %s: %s", m, c.name, d)
			} else {
				t.Logf("ok [%s] %s panicked=%v %s", m, c.name, a.panicked, a.pstr)
			}
		}
		cleanup()
	}
}
