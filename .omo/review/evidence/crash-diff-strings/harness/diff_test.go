package crashdiff

import (
	"context"
	"fmt"
	"iter"
	"math"
	"math/rand/v2"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

type outcome struct {
	Strs  []string
	Bools []bool
	Ints  []int
	Err   string
	Panic string
	Count int
}

type kind int

const (
	kindExact  kind = iota // tainted bytes must come from a source
	kindCoarse             // bounds/source checks only
)

type env struct {
	a, b, c, d string
	bs         []byte
	n, k       int
	chain      []byte
	rep        *strings.Replacer
	ps         *ptrStringer
	coarsened  bool // a derives from a coarse op: exact byte checks no longer apply
}

type op struct {
	name      string
	kind      kind
	panicOnly bool // compare panic presence only (slice-message reference differs)
	window    bool // outputs aliasing a tainted input must be tainted
	f         func(im *Impl, e *env) outcome
}

type myString string
type myBytes []byte
type counter struct{}

var stringerCalls int

func (counter) String() string { stringerCalls++; return "S" }

type boom struct{}

func (boom) String() string { panic("boom") }

type ptrStringer struct{ v string }

func (p *ptrStringer) String() string { return p.v }

func collect(seq iter.Seq[string], stop int) []string {
	var out []string
	for v := range seq {
		out = append(out, v)
		if stop > 0 && len(out) >= stop {
			break
		}
	}
	return out
}

func pred(sel int, cnt *int) func(rune) bool {
	return func(r rune) bool {
		*cnt++
		switch sel % 4 {
		case 0:
			return unicode.IsSpace(r)
		case 1:
			return unicode.IsLetter(r)
		case 2:
			return r == ',' || r == utf8.RuneError
		default:
			return r < 'm'
		}
	}
}

func mapping(sel int, cnt *int) func(rune) rune {
	return func(r rune) rune {
		*cnt++
		switch sel % 5 {
		case 0:
			return r
		case 1:
			return unicode.ToUpper(r)
		case 2:
			if r == 'a' {
				return -1
			}
			return r
		case 3:
			return 0x110000
		default:
			return r + 1
		}
	}
}

func fmtArgs(e *env) []any {
	var nilp *ptrStringer
	all := []any{e.a, e.bs, myString(e.b), counter{}, e.n, nil, myBytes(e.bs), e.c, boom{}, nilp, e.ps, e.d, []string{e.a, e.b}, struct{ S string }{e.a}, &e.a, 3.5, e.bs[:0:0], []myString{myString(e.a)}}
	return all[:e.k%(len(all)+1)]
}

func repeatCount(e *env) int {
	n := e.n % 50
	if e.k == 7 && len(e.a) >= 2 {
		return math.MaxInt
	}
	if n > 0 && len(e.a)*n > 1<<14 {
		return 2
	}
	return n
}

var ops = []op{
	{name: "Clone", f: func(im *Impl, e *env) outcome { return outcome{Strs: []string{im.Clone(e.a)}} }},
	{name: "CloneStale", f: func(im *Impl, e *env) outcome { return outcome{Strs: []string{im.Clone(e.d)}} }},
	{name: "Cut", window: true, f: func(im *Impl, e *env) outcome {
		x, y, ok := im.Cut(e.a, e.b)
		return outcome{Strs: []string{x, y}, Bools: []bool{ok}}
	}},
	{name: "CutPrefix", window: true, f: func(im *Impl, e *env) outcome {
		x, ok := im.CutPrefix(e.a, e.b)
		return outcome{Strs: []string{x}, Bools: []bool{ok}}
	}},
	{name: "CutSuffix", window: true, f: func(im *Impl, e *env) outcome {
		x, ok := im.CutSuffix(e.a, e.b)
		return outcome{Strs: []string{x}, Bools: []bool{ok}}
	}},
	{name: "Split", window: true, f: func(im *Impl, e *env) outcome { return outcome{Strs: im.Split(e.a, e.b)} }},
	{name: "SplitN", window: true, f: func(im *Impl, e *env) outcome { return outcome{Strs: im.SplitN(e.a, e.b, e.n%40-5)} }},
	{name: "SplitAfter", window: true, f: func(im *Impl, e *env) outcome { return outcome{Strs: im.SplitAfter(e.a, e.b)} }},
	{name: "SplitAfterN", window: true, f: func(im *Impl, e *env) outcome { return outcome{Strs: im.SplitAfterN(e.a, e.b, e.n%40-5)} }},
	{name: "SplitSeq", window: true, f: func(im *Impl, e *env) outcome {
		seq := im.SplitSeq(e.a, e.b)
		return outcome{Strs: append(collect(seq, e.k%5), collect(seq, 0)...)}
	}},
	{name: "SplitAfterSeq", window: true, f: func(im *Impl, e *env) outcome {
		return outcome{Strs: collect(im.SplitAfterSeq(e.a, e.b), e.k%5)}
	}},
	{name: "Lines", window: true, f: func(im *Impl, e *env) outcome { return outcome{Strs: collect(im.Lines(e.a), e.k%5)} }},
	{name: "Fields", window: true, f: func(im *Impl, e *env) outcome { return outcome{Strs: im.Fields(e.a)} }},
	{name: "FieldsFunc", window: true, f: func(im *Impl, e *env) outcome {
		var cnt int
		r := im.FieldsFunc(e.a, pred(e.k, &cnt))
		return outcome{Strs: r, Count: cnt}
	}},
	{name: "FieldsSeq", window: true, f: func(im *Impl, e *env) outcome { return outcome{Strs: collect(im.FieldsSeq(e.a), e.k%5)} }},
	{name: "FieldsFuncSeq", window: true, f: func(im *Impl, e *env) outcome {
		var cnt int
		r := collect(im.FieldsFuncSeq(e.a, pred(e.k, &cnt)), e.k%5)
		return outcome{Strs: r, Count: cnt}
	}},
	{name: "Join", f: func(im *Impl, e *env) outcome {
		return outcome{Strs: []string{im.Join([]string{e.a, e.b, e.d}, e.c), im.Join([]string{e.a}, ""), im.Join([]string{"", e.a, ""}, ""), im.Join(nil, e.a)}}
	}},
	{name: "JoinSplit", kind: kindCoarse, f: func(im *Impl, e *env) outcome {
		parts := im.Split(e.a, e.b)
		return outcome{Strs: []string{im.Join(parts, e.c), im.Join(parts, "")}}
	}},
	{name: "JoinMany", kind: kindCoarse, f: func(im *Impl, e *env) outcome {
		parts := make([]string, 17+e.k%3)
		for i := range parts {
			parts[i] = e.a
		}
		return outcome{Strs: []string{im.Join(parts, e.b)}}
	}},
	{name: "Repeat", f: func(im *Impl, e *env) outcome { return outcome{Strs: []string{im.Repeat(e.a, repeatCount(e))}} }},
	{name: "Replace", kind: kindCoarse, f: func(im *Impl, e *env) outcome {
		return outcome{Strs: []string{im.Replace(e.a, e.b, e.c, e.n%40-5), im.Replace(e.a, "", e.c, e.n%40-5)}}
	}},
	{name: "ReplaceAll", kind: kindCoarse, f: func(im *Impl, e *env) outcome {
		return outcome{Strs: []string{im.ReplaceAll(e.a, e.b, e.c), im.ReplaceAll(e.a, "", e.c)}}
	}},
	{name: "Replacer", kind: kindCoarse, f: func(im *Impl, e *env) outcome { return outcome{Strs: []string{im.ReplacerRepl(e.rep, e.a)}} }},
	{name: "Trim", window: true, f: func(im *Impl, e *env) outcome { return outcome{Strs: []string{im.Trim(e.a, e.b)}} }},
	{name: "TrimSpace", window: true, f: func(im *Impl, e *env) outcome { return outcome{Strs: []string{im.TrimSpace(e.a)}} }},
	{name: "TrimLeft", window: true, f: func(im *Impl, e *env) outcome { return outcome{Strs: []string{im.TrimLeft(e.a, e.b)}} }},
	{name: "TrimRight", window: true, f: func(im *Impl, e *env) outcome { return outcome{Strs: []string{im.TrimRight(e.a, e.b)}} }},
	{name: "TrimPrefix", window: true, f: func(im *Impl, e *env) outcome { return outcome{Strs: []string{im.TrimPrefix(e.a, e.b)}} }},
	{name: "TrimSuffix", window: true, f: func(im *Impl, e *env) outcome { return outcome{Strs: []string{im.TrimSuffix(e.a, e.b)}} }},
	{name: "TrimFunc", window: true, f: func(im *Impl, e *env) outcome {
		var cnt int
		return outcome{Strs: []string{im.TrimFunc(e.a, pred(e.k, &cnt))}, Count: cnt}
	}},
	{name: "TrimLeftFunc", window: true, f: func(im *Impl, e *env) outcome {
		var cnt int
		return outcome{Strs: []string{im.TrimLeftFunc(e.a, pred(e.k, &cnt))}, Count: cnt}
	}},
	{name: "TrimRightFunc", window: true, f: func(im *Impl, e *env) outcome {
		var cnt int
		return outcome{Strs: []string{im.TrimRightFunc(e.a, pred(e.k, &cnt))}, Count: cnt}
	}},
	{name: "ToLower", kind: kindCoarse, f: func(im *Impl, e *env) outcome { return outcome{Strs: []string{im.ToLower(e.a)}} }},
	{name: "ToUpper", kind: kindCoarse, f: func(im *Impl, e *env) outcome { return outcome{Strs: []string{im.ToUpper(e.a)}} }},
	{name: "ToTitle", kind: kindCoarse, f: func(im *Impl, e *env) outcome { return outcome{Strs: []string{im.ToTitle(e.a)}} }},
	{name: "Map", kind: kindCoarse, f: func(im *Impl, e *env) outcome {
		var cnt int
		return outcome{Strs: []string{im.Map(mapping(e.k, &cnt), e.a)}, Count: cnt}
	}},
	{name: "ToValidUTF8", kind: kindCoarse, f: func(im *Impl, e *env) outcome {
		return outcome{Strs: []string{im.ToValidUTF8(e.a, e.b), im.ToValidUTF8(e.a, "")}}
	}},
	{name: "Sprint", kind: kindCoarse, f: func(im *Impl, e *env) outcome {
		before := stringerCalls
		r := im.Sprint(fmtArgs(e)...)
		return outcome{Strs: []string{r, im.Sprint(e.a), im.Sprint(e.a, e.b)}, Count: stringerCalls - before}
	}},
	{name: "Sprintf", kind: kindCoarse, f: func(im *Impl, e *env) outcome {
		before := stringerCalls
		r := im.Sprintf(e.c, fmtArgs(e)...)
		return outcome{Strs: []string{r, im.Sprintf(e.a), im.Sprintf("%s|%q|%x|%v", e.a, e.b, e.bs, e.d)}, Count: stringerCalls - before}
	}},
	{name: "Sprintln", kind: kindCoarse, f: func(im *Impl, e *env) outcome {
		before := stringerCalls
		r := im.Sprintln(fmtArgs(e)...)
		return outcome{Strs: []string{r}, Count: stringerCalls - before}
	}},
	{name: "SprintMany", kind: kindCoarse, f: func(im *Impl, e *env) outcome {
		args := make([]any, 17)
		for i := range args {
			args[i] = e.b
		}
		args[0], args[16] = e.a, e.c
		return outcome{Strs: []string{im.Sprint(args...), im.Sprintf(strings.Repeat("%v", 17), args...), im.Sprintln(args...)}}
	}},
	{name: "QueryEscape", kind: kindCoarse, f: func(im *Impl, e *env) outcome { return outcome{Strs: []string{im.QueryEscape(e.a)}} }},
	{name: "PathEscape", kind: kindCoarse, f: func(im *Impl, e *env) outcome { return outcome{Strs: []string{im.PathEscape(e.a)}} }},
	{name: "QueryUnescape", kind: kindCoarse, f: func(im *Impl, e *env) outcome {
		r, err := im.QueryUnescape(e.a)
		return outcome{Strs: []string{r}, Err: errString(err)}
	}},
	{name: "PathUnescape", kind: kindCoarse, f: func(im *Impl, e *env) outcome {
		r, err := im.PathUnescape(e.a)
		return outcome{Strs: []string{r}, Err: errString(err)}
	}},
	{name: "RoundTripURL", kind: kindCoarse, f: func(im *Impl, e *env) outcome {
		r, err := im.QueryUnescape(im.QueryEscape(e.a))
		p, err2 := im.PathUnescape(im.PathEscape(e.a))
		return outcome{Strs: []string{r, p}, Err: errString(err) + "|" + errString(err2)}
	}},
	{name: "Quote", kind: kindCoarse, f: func(im *Impl, e *env) outcome {
		return outcome{Strs: []string{im.Quote(e.a), im.QuoteToASCII(e.a), im.QuoteToGraphic(e.a)}}
	}},
	{name: "Unquote", kind: kindCoarse, f: func(im *Impl, e *env) outcome {
		r, err := im.Unquote(e.a)
		q, err2 := im.Unquote(im.Quote(e.a))
		return outcome{Strs: []string{r, q}, Err: errString(err) + "|" + errString(err2)}
	}},
	{name: "Builder", f: builderOp},
	{name: "Concat", f: func(im *Impl, e *env) outcome {
		var v16 [16]string
		var v17 [17]string
		for i := range v16 {
			v16[i] = []string{e.a, e.b, e.c, e.d}[i%4]
		}
		for i := range v17 {
			v17[i] = []string{e.a, e.b, e.c, e.d}[i%4]
		}
		return outcome{Strs: []string{im.Concat2(e.a, e.b), im.Concat2("", e.a), im.Concat2(e.a, ""), im.Concat3(e.a, e.d, e.c), im.Concat16(v16), im.Concat17(v17)}}
	}},
	{name: "Slice", window: true, panicOnly: true, f: func(im *Impl, e *env) outcome {
		i, j := e.n%(len(e.a)+3)-1, e.k%(len(e.a)+3)-1
		return outcome{Strs: []string{im.Slice(e.a, i, j)}}
	}},
	{name: "SliceLowHigh", window: true, panicOnly: true, f: func(im *Impl, e *env) outcome {
		i := e.n % (len(e.a) + 2)
		return outcome{Strs: []string{im.SliceLow(e.a, i), im.SliceHigh(e.a, e.k%(len(e.a)+2))}}
	}},
	{name: "B2S", f: func(im *Impl, e *env) outcome { return outcome{Strs: []string{im.B2S(e.bs), im.B2S(nil)}} }},
	{name: "B2SSlice", panicOnly: true, f: func(im *Impl, e *env) outcome {
		i, j := e.n%(cap(e.bs)+2), e.k%(cap(e.bs)+2)
		return outcome{Strs: []string{im.B2SSlice(e.bs, i, j)}}
	}},
}

func builderOp(im *Impl, e *env) outcome {
	var out outcome
	var b strings.Builder
	record := func() {
		out.Ints = append(out.Ints, b.Len(), b.Cap())
	}
	steps := e.chain
	if len(steps) > 16 {
		steps = steps[:16]
	}
	for _, s := range steps {
		switch s % 9 {
		case 0:
			n, err := im.BWriteString(&b, e.a)
			out.Ints = append(out.Ints, n)
			out.Err += errString(err)
		case 1:
			n, err := im.BWriteString(&b, e.b)
			out.Ints = append(out.Ints, n)
			out.Err += errString(err)
		case 2:
			n, err := im.BWrite(&b, e.bs)
			out.Ints = append(out.Ints, n)
			out.Err += errString(err)
		case 3:
			out.Err += errString(im.BWriteByte(&b, byte(e.n)))
		case 4:
			n, err := im.BWriteRune(&b, rune(e.n))
			out.Ints = append(out.Ints, n)
			out.Err += errString(err)
		case 5:
			im.BGrow(&b, e.k%70-5)
		case 6:
			im.BReset(&b)
		case 7:
			out.Strs = append(out.Strs, im.BString(&b))
		case 8:
			n, err := im.BCopyWrite(&b, e.a)
			out.Ints = append(out.Ints, n)
			out.Err += errString(err)
		}
		record()
	}
	out.Strs = append(out.Strs, im.BString(&b))
	return out
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return reflect.TypeOf(err).String() + ":" + err.Error()
}

func call(im *Impl, o *op, e *env) (out outcome) {
	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(error); ok {
				out = outcome{Panic: "error:" + err.Error()}
			} else {
				out = outcome{Panic: fmt.Sprint(r)}
			}
		}
	}()
	return o.f(im, e)
}

func equalOutcome(o *op, x, y outcome) bool {
	if o.panicOnly && (x.Panic != "" || y.Panic != "") {
		return (x.Panic != "") == (y.Panic != "")
	}
	norm := func(v outcome) outcome {
		if len(v.Strs) == 0 {
			v.Strs = nil
		}
		if len(v.Ints) == 0 {
			v.Ints = nil
		}
		return v
	}
	return reflect.DeepEqual(norm(x), norm(y))
}

// ---------------- stats ----------------

type opStats struct {
	calls, taintedIn, taintedOut, windowMiss, aliasMismatch, panics atomic.Int64
}

var (
	statsMu sync.Mutex
	stats   = map[string]*opStats{}
	iterNo  atomic.Int64
	stale   []string
	staleMu sync.Mutex
)

func statFor(name string) *opStats {
	statsMu.Lock()
	defer statsMu.Unlock()
	s := stats[name]
	if s == nil {
		s = &opStats{}
		stats[name] = s
	}
	return s
}

func aliasOf(v string, inputs ...string) bool {
	if len(v) == 0 {
		return false
	}
	p := uintptr(unsafe.Pointer(unsafe.StringData(v)))
	for _, in := range inputs {
		if len(in) == 0 {
			continue
		}
		base := uintptr(unsafe.Pointer(unsafe.StringData(in)))
		if p >= base && p+uintptr(len(v)) <= base+uintptr(len(in)) {
			return true
		}
	}
	return false
}

func setup() {
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
}

type sourceInfo struct{ value string }

// runCase executes one differential case and returns a non-empty failure
// description on divergence or taint-oracle violation.
func runCase(a, b, c string, n int, flags uint8, chain []byte) string {
	it := iterNo.Add(1)
	suffix := "#" + strconv.FormatInt(it, 10)
	allowed := map[string]string{}
	ctx1, scope1, _ := request.Begin(context.Background())
	ctx2 := ctx1
	var scope2 *request.Scope
	if flags&8 != 0 {
		ctx2, scope2, _ = request.Begin(context.Background())
	}
	defer func() {
		scope1.Finish()
		if scope2 != nil {
			scope2.Finish()
		}
	}()
	e := &env{a: a, b: b, c: c, n: n, k: int(flags>>4) + len(chain), chain: chain}
	if e.n < 0 {
		e.n = -e.n
		if e.n < 0 {
			e.n = 0
		}
	}
	taintS := func(ctx context.Context, name, v string) string {
		name += suffix
		r := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: name}, v)
		if taint.IsTaintedString(r) {
			allowed[name] = v
		}
		return r
	}
	if flags&1 != 0 {
		e.a = taintS(ctx1, "A", e.a)
	}
	if flags&2 != 0 {
		e.b = taintS(ctx2, "B", e.b)
	}
	if flags&4 != 0 {
		e.c = taintS(ctx1, "C", e.c)
	}
	e.bs = []byte(b)
	if flags&2 != 0 {
		name := "BS" + suffix
		r := taint.TaintBytes(ctx2, taint.Source{Origin: taint.OriginHttpRequestBody, Name: name}, e.bs)
		if taint.IsTaintedBytes(r) {
			allowed[name] = b
		}
		e.bs = r
	}
	if flags&32 != 0 && flags&1 != 0 {
		e.b = e.a // same tainted value used twice
	}
	staleMu.Lock()
	if len(stale) > 0 {
		e.d = stale[int(it)%len(stale)]
	} else {
		e.d = "stale-seed"
	}
	staleMu.Unlock()
	e.ps = &ptrStringer{e.a}
	if len(e.b)%2 == 0 {
		e.rep = strings.NewReplacer(e.b, e.c, e.c, e.a)
	} else {
		e.rep = strings.NewReplacer(e.b, e.c)
	}

	var produced []string
	check := func(o *op, cur *env) string {
		st := statFor(o.name)
		st.calls.Add(1)
		w := call(&Woven, o, cur)
		nat := call(&Native, o, cur)
		ref := call(&Reflect, o, cur)
		if !equalOutcome(o, w, nat) || !equalOutcome(o, w, ref) {
			return fmt.Sprintf("DIVERGENCE op=%s\n a=%q b=%q c=%q d=%q n=%d k=%d chain=%v\n woven =%#v\n native=%#v\n reflect=%#v", o.name, cur.a, cur.b, cur.c, cur.d, cur.n, cur.k, cur.chain, w, nat, ref)
		}
		if w.Panic != "" {
			st.panics.Add(1)
			return ""
		}
		inTainted := false
		for _, in := range []string{cur.a, cur.b, cur.c, cur.d} {
			if taint.IsTaintedString(in) {
				inTainted = true
			}
		}
		if taint.IsTaintedBytes(cur.bs) {
			inTainted = true
		}
		if inTainted {
			st.taintedIn.Add(1)
		}
		for idx, s := range w.Strs {
			if idx < len(nat.Strs) && aliasOf(s, cur.a, cur.b, cur.c, cur.d) != aliasOf(nat.Strs[idx], cur.a, cur.b, cur.c, cur.d) {
				st.aliasMismatch.Add(1)
			}
			var bad string
			tainted := taint.VisitString(s, func(r taint.Range) bool {
				end := uint64(r.Start) + uint64(r.Length)
				if r.Length == 0 || end > uint64(len(s)) {
					bad = fmt.Sprintf("range out of bounds start=%d len=%d strlen=%d", r.Start, r.Length, len(s))
					return false
				}
				want, ok := allowed[r.Source.Name]
				if !ok {
					bad = fmt.Sprintf("unexpected source %q (allowed %v) -- cross-iteration/false taint", r.Source.Name, allowed)
					return false
				}
				if want != r.Source.Value {
					bad = fmt.Sprintf("source value mismatch name=%q got=%q want=%q", r.Source.Name, r.Source.Value, want)
					return false
				}
				if o.kind == kindExact && !cur.coarsened {
					for _, ch := range []byte(s[r.Start:end]) {
						if strings.IndexByte(want, ch) < 0 {
							bad = fmt.Sprintf("exact range [%d,%d) covers byte %q not present in source %q value %q", r.Start, end, ch, r.Source.Name, want)
							return false
						}
					}
				}
				return true
			})
			if bad != "" {
				return fmt.Sprintf("TAINT-ORACLE op=%s out[%d]=%q: %s\n a=%q b=%q c=%q d=%q n=%d k=%d chain=%v flags=%d", o.name, idx, s, bad, cur.a, cur.b, cur.c, cur.d, cur.n, cur.k, cur.chain, flags)
			}
			if tainted {
				st.taintedOut.Add(1)
				produced = append(produced, s)
			} else if o.window && idx < 32 && len(s) > 0 && taint.IsTaintedString(cur.a) && aliasOf(s, cur.a) {
				st.windowMiss.Add(1)
				missMu.Lock()
				if len(misses) < 200 {
					cp := *cur
					cp.a = strings.Clone(cur.a)
					misses = append(misses, miss{o: o, e: cp, idx: idx})
				}
				missMu.Unlock()
			}
		}
		return ""
	}

	for i := range ops {
		if msg := check(&ops[i], e); msg != "" {
			return msg
		}
	}
	// Chain: feed woven outputs forward.
	cur := *e
	for _, step := range chain {
		if len(cur.a) > 1<<12 {
			break // harness bound: chained Join/Repeat/Replace grow exponentially
		}
		o := &ops[int(step)%len(ops)]
		if msg := check(o, &cur); msg != "" {
			return "CHAIN " + msg
		}
		w := call(&Woven, o, &cur)
		if w.Panic == "" && len(w.Strs) > 0 {
			cur.a = w.Strs[int(step)%len(w.Strs)]
			cur.coarsened = cur.coarsened || o.kind == kindCoarse
		}
	}
	staleMu.Lock()
	stale = append(stale, produced...)
	if len(stale) > 16 {
		stale = stale[len(stale)-16:]
	}
	staleMu.Unlock()
	if it%512 == 0 {
		runtime.GC()
	}
	return ""
}

func requireWoven(t testing.TB) {
	if !built.WithOrchestrion {
		t.Fatal("not woven: run with `go tool orchestrion go test`")
	}
}

// TestWeavingAsymmetry proves Woven is instrumented and Native/Reflect are not.
func TestWeavingAsymmetry(t *testing.T) {
	requireWoven(t)
	setup()
	ctx, scope, created := request.Begin(context.Background())
	if !created {
		t.Fatal("no scope")
	}
	defer scope.Finish()
	v := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "x"}, "attack value")
	if !taint.IsTaintedString(v) {
		t.Fatal("source not tainted")
	}
	for _, c := range []struct {
		name   string
		w, n   string
		rf     string
		wantWV bool
	}{
		{"Clone", Woven.Clone(v), Native.Clone(v), Reflect.Clone(v), true},
		{"ToUpper", Woven.ToUpper(v), Native.ToUpper(v), Reflect.ToUpper(v), true},
		{"Quote", Woven.Quote(v), Native.Quote(v), Reflect.Quote(v), true},
		{"QueryEscape", Woven.QueryEscape(v), Native.QueryEscape(v), Reflect.QueryEscape(v), true},
		{"Sprintf", Woven.Sprintf("%s!", v), Native.Sprintf("%s!", v), Reflect.Sprintf("%s!", v), true},
		{"Concat2", Woven.Concat2(v, "!"), Native.Concat2(v, "!"), Reflect.Concat2(v, "!"), true},
		{"Repeat", Woven.Repeat(v, 2), Native.Repeat(v, 2), Reflect.Repeat(v, 2), true},
	} {
		if taint.IsTaintedString(c.w) != c.wantWV || taint.IsTaintedString(c.n) || taint.IsTaintedString(c.rf) {
			t.Fatalf("%s: woven=%v native=%v reflect=%v", c.name, taint.IsTaintedString(c.w), taint.IsTaintedString(c.n), taint.IsTaintedString(c.rf))
		}
		if c.w != c.n || c.w != c.rf {
			t.Fatalf("%s: content divergence", c.name)
		}
	}
	nativeParts := Native.Split(v, " ")
	if taint.IsTaintedString(nativeParts[0]) {
		t.Fatal("native split tainted")
	}
	if parts := Woven.Split(v, " "); !taint.IsTaintedString(parts[0]) {
		t.Fatal("split asymmetry not observed")
	}
}

var seedStrings = []string{
	"", "a", "ab", "  alpha,beta  ", "%zz", "%41%42+x", `"quoted\n"`, "\xff\xfeab", "ǅǆǄ", "İstanbul", "ẞß", "a\nb\r\nc\n",
	"%s%v%d%q%x%!%", "x,y,,z,", "SELECT * FROM t WHERE a='", "../../etc/passwd", "\u0000\u0001", "Σσς", "\u212a", "'\"`", ",",
	strings.Repeat("ab,", 40), "日本語,テキスト", "a b\tc\u00a0d\u2003e",
}

func randString(r *rand.Rand) string {
	var sb []byte
	for range r.IntN(5) {
		s := seedStrings[r.IntN(len(seedStrings))]
		sb = append(sb, s...)
		if r.IntN(4) == 0 && len(sb) > 0 {
			sb = sb[:r.IntN(len(sb))]
		}
	}
	return string(sb)
}

type miss struct {
	o   *op
	e   env
	idx int
}

var (
	missMu sync.Mutex
	misses []miss
)

// recheckMisses replays each window miss in a fresh request where only a is
// tainted and reports those that still miss.
func recheckMisses(t *testing.T) {
	missMu.Lock()
	list := misses
	misses = nil
	missMu.Unlock()
	still := 0
	for _, m := range list {
		ctx, scope, _ := request.Begin(context.Background())
		e := m.e
		e.a = taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "iso"}, e.a)
		e.b, e.c, e.d = strings.Clone(e.b), strings.Clone(e.c), strings.Clone(e.d)
		e.bs = append([]byte(nil), e.bs...)
		if !taint.IsTaintedString(e.a) {
			scope.Finish()
			continue
		}
		w := call(&Woven, m.o, &e)
		if w.Panic == "" && m.idx < len(w.Strs) {
			out := w.Strs[m.idx]
			if len(out) > 0 && aliasOf(out, e.a) && !taint.IsTaintedString(out) {
				still++
				if still <= 15 {
					t.Logf("ISOLATED WINDOW MISS op=%s idx=%d out=%q a=%q b=%q c=%q n=%d k=%d chain=%v", m.o.name, m.idx, out, e.a, e.b, e.c, e.n, e.k, e.chain)
				}
			}
		}
		scope.Finish()
	}
	t.Logf("window misses recorded=%d, still missing in isolation=%d", len(list), still)
}

// TestDiffRandom runs a PRNG-driven campaign and prints per-op statistics.
func TestDiffRandom(t *testing.T) {
	requireWoven(t)
	setup()
	iters := 20000
	if v := os.Getenv("CRASHDIFF_ITERS"); v != "" {
		iters, _ = strconv.Atoi(v)
	}
	seed := uint64(1)
	if v := os.Getenv("CRASHDIFF_SEED"); v != "" {
		seed, _ = strconv.ParseUint(v, 10, 64)
	}
	r := rand.New(rand.NewPCG(seed, 7))
	for i := 0; i < iters; i++ {
		chain := make([]byte, r.IntN(12))
		for j := range chain {
			chain[j] = byte(r.IntN(256))
		}
		if msg := runCase(randString(r), randString(r), randString(r), r.IntN(1000)-100, uint8(r.IntN(256)), chain); msg != "" {
			t.Fatalf("iteration %d: %s", i, msg)
		}
	}
	recheckMisses(t)
	names := make([]string, 0, len(stats))
	for k := range stats {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		s := stats[k]
		t.Logf("%-14s calls=%7d taintedIn=%7d taintedOut=%7d windowMiss=%5d aliasMismatch=%5d panics=%5d", k, s.calls.Load(), s.taintedIn.Load(), s.taintedOut.Load(), s.windowMiss.Load(), s.aliasMismatch.Load(), s.panics.Load())
	}
}

func FuzzStringsDiff(f *testing.F) {
	setup()
	for i, s := range seedStrings {
		f.Add(s, seedStrings[(i+3)%len(seedStrings)], seedStrings[(i+7)%len(seedStrings)], i*37, uint8(i*29), []byte{byte(i), byte(i * 7), byte(i * 13)})
	}
	f.Fuzz(func(t *testing.T, a, b, c string, n int, flags uint8, chain []byte) {
		requireWoven(t)
		if len(a)+len(b)+len(c) > 4096 {
			return
		}
		if len(chain) > 24 {
			chain = chain[:24]
		}
		if msg := runCase(a, b, c, n, flags, chain); msg != "" {
			t.Fatal(msg)
		}
	})
}
