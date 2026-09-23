// Differential fidelity harness (review node hooks-fidelity-bytes).
// Calls every iast/propagation bytes wrapper and every strings.Builder /
// bytes.Buffer writer wrapper directly, and the uninstrumented stdlib
// operation with identical inputs, in four modes, and asserts identical
// results, panics, side effects, result aliasing (offset/len/cap relative to
// every input backing array), mutation-through-result visibility, and writer
// state (Len, Cap, Available, String, Bytes offset, lastRead probes).
// Run WITHOUT orchestrion so the reference calls stay native.

package propagation_test

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"reflect"
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

type fbMode int

const (
	fbInactive fbMode = iota
	fbActiveClean
	fbTainted
	fbForeign
)

func (m fbMode) String() string {
	return [...]string{"inactive", "active-clean", "tainted", "foreign-owners"}[m]
}

type fbEnv struct {
	t      *testing.T
	ctxs   []context.Context
	scopes []*request.Scope
}

func (e *fbEnv) begin(n int) {
	for i := 0; i < n; i++ {
		ctx, scope, created := request.Begin(context.Background())
		if !created || scope == nil {
			e.t.Fatalf("request.Begin did not create a scope")
		}
		e.ctxs = append(e.ctxs, ctx)
		e.scopes = append(e.scopes, scope)
	}
}

func (e *fbEnv) startMode(mode fbMode) {
	switch mode {
	case fbActiveClean, fbTainted:
		e.begin(1)
	case fbForeign:
		e.begin(3)
	}
	if mode == fbInactive && request.ActiveStore() != nil {
		e.t.Fatalf("store unexpectedly active")
	}
	if mode != fbInactive && request.ActiveStore() == nil {
		e.t.Fatalf("store not active in %v", mode)
	}
}

func (e *fbEnv) finish() {
	for _, s := range e.scopes {
		s.Finish()
	}
	e.ctxs, e.scopes = nil, nil
}

// taintB returns a tainted managed copy of v (or v itself when mode does not taint).
func (e *fbEnv) taintB(mode fbMode, i int, v []byte) []byte {
	if v == nil || len(v) == 0 {
		return v
	}
	switch mode {
	case fbTainted:
		return taint.TaintBytes(e.ctxs[0], taint.Source{Origin: taint.OriginHttpRequestBody, Name: "b" + strconv.Itoa(i)}, v)
	case fbForeign:
		return taint.TaintBytes(e.ctxs[i%len(e.ctxs)], taint.Source{Origin: taint.OriginHttpRequestHeader, Name: "h" + strconv.Itoa(i)}, v)
	}
	return v
}

func (e *fbEnv) taintS(mode fbMode, i int, v string) string {
	if v == "" {
		return v
	}
	switch mode {
	case fbTainted:
		return taint.TaintString(e.ctxs[0], taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "s" + strconv.Itoa(i)}, v)
	case fbForeign:
		return taint.TaintString(e.ctxs[i%len(e.ctxs)], taint.Source{Origin: taint.OriginHttpRequestHeader, Name: "sh" + strconv.Itoa(i)}, v)
	}
	return v
}

func fbConfig(t *testing.T) {
	pe, ps, pm := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() { config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = pe, ps, pm })
}

func fbIterations() int {
	if v, err := strconv.Atoi(os.Getenv("FIDELITY_ITERS")); err == nil && v > 0 {
		return v
	}
	return 400
}

// --- slice descriptors -------------------------------------------------------

// sliceDesc describes a result slice in caller-observable, allocation-
// independent terms: nil-ness, len, cap, content, and which input backing array
// (if any) it aliases and at what offset from that input's data pointer.
func sliceDesc(s []byte, inputs [][]byte) string {
	if s == nil {
		return "nil"
	}
	alias := "fresh"
	p := uintptr(unsafe.Pointer(unsafe.SliceData(s)))
	for i, in := range inputs {
		if cap(in) == 0 {
			continue
		}
		base := uintptr(unsafe.Pointer(unsafe.SliceData(in)))
		if p >= base && p <= base+uintptr(cap(in)) && (cap(s) == 0 || p < base+uintptr(cap(in))) {
			alias = fmt.Sprintf("alias(in%d,+%d)", i, p-base)
			break
		}
	}
	return fmt.Sprintf("len=%d cap=%d %s %q", len(s), cap(s), alias, s)
}

type fbOutcome struct {
	vals     []string
	panicked bool
	pv       string
}

func fbCapture(f func() []string) (o fbOutcome) {
	defer func() {
		if r := recover(); r != nil {
			o.panicked = true
			o.pv = fmt.Sprintf("%T: %v", r, r)
		}
	}()
	o.vals = f()
	return
}

// fullView returns the whole backing array visible through cap.
func fullView(b []byte) []byte { return b[:cap(b)] }

func cloneCap(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b), cap(b))
	copy(c[:cap(b)], b[:cap(b)])
	return c
}

// --- predicates with observable side effects ---------------------------------

type fbCounter struct{ n int }

func (c *fbCounter) space(r rune) bool { c.n++; return unicode.IsSpace(r) }
func (c *fbCounter) comma(r rune) bool { c.n++; return r == ',' || r == utf8Err }
func (c *fbCounter) mapr(r rune) rune {
	c.n++
	switch {
	case r == 'x':
		return -1
	case r == '!':
		panic("mapping boom")
	case r == 'a':
		return 'ÿ'
	case r == 'é':
		return 'e'
	}
	return unicode.ToUpper(r)
}

const utf8Err = '\uFFFD'

// --- byte cases --------------------------------------------------------------

type byteArgs struct {
	a, b, c []byte
	elems   [][]byte
	cut     string
	n       int
}

type byteCase struct {
	name string
	// run executes the operation; wrap selects the wrapper. It returns the
	// result slices (for aliasing and mutation checks) and scalar values.
	run func(wrap bool, x *byteArgs) (results [][]byte, scalars []string)
}

func descAll(results [][]byte, scalars []string, x *byteArgs) []string {
	inputs := [][]byte{x.a, x.b, x.c}
	inputs = append(inputs, x.elems...)
	out := append([]string(nil), scalars...)
	for _, r := range results {
		out = append(out, sliceDesc(r, inputs))
	}
	return out
}

func one(r []byte) [][]byte { return [][]byte{r} }

func splitRes(tag string, r [][]byte) ([][]byte, []string) {
	return r, []string{fmt.Sprintf("%s nil=%v len=%d cap=%d", tag, r == nil, len(r), cap(r))}
}

func byteCases() []byteCase {
	return []byteCase{
		{"Clone", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return one(iastprop.BytesClone(x.a)), nil
			}
			return one(bytes.Clone(x.a)), nil
		}},
		{"Join", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return one(iastprop.BytesJoin(x.elems, x.b)), nil
			}
			return one(bytes.Join(x.elems, x.b)), nil
		}},
		{"Repeat", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return one(iastprop.BytesRepeat(x.a, x.n)), nil
			}
			return one(bytes.Repeat(x.a, x.n)), nil
		}},
		{"Cut", func(w bool, x *byteArgs) ([][]byte, []string) {
			var b, a []byte
			var f bool
			if w {
				b, a, f = iastprop.BytesCut(x.a, x.b)
			} else {
				b, a, f = bytes.Cut(x.a, x.b)
			}
			return [][]byte{b, a}, []string{strconv.FormatBool(f)}
		}},
		{"CutPrefix", func(w bool, x *byteArgs) ([][]byte, []string) {
			var a []byte
			var f bool
			if w {
				a, f = iastprop.BytesCutPrefix(x.a, x.b)
			} else {
				a, f = bytes.CutPrefix(x.a, x.b)
			}
			return one(a), []string{strconv.FormatBool(f)}
		}},
		{"CutSuffix", func(w bool, x *byteArgs) ([][]byte, []string) {
			var a []byte
			var f bool
			if w {
				a, f = iastprop.BytesCutSuffix(x.a, x.b)
			} else {
				a, f = bytes.CutSuffix(x.a, x.b)
			}
			return one(a), []string{strconv.FormatBool(f)}
		}},
		{"Split", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return splitRes("s", iastprop.BytesSplit(x.a, x.b))
			}
			return splitRes("s", bytes.Split(x.a, x.b))
		}},
		{"SplitN", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return splitRes("s", iastprop.BytesSplitN(x.a, x.b, x.n))
			}
			return splitRes("s", bytes.SplitN(x.a, x.b, x.n))
		}},
		{"SplitAfter", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return splitRes("s", iastprop.BytesSplitAfter(x.a, x.b))
			}
			return splitRes("s", bytes.SplitAfter(x.a, x.b))
		}},
		{"SplitAfterN", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return splitRes("s", iastprop.BytesSplitAfterN(x.a, x.b, x.n))
			}
			return splitRes("s", bytes.SplitAfterN(x.a, x.b, x.n))
		}},
		{"Fields", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return splitRes("s", iastprop.BytesFields(x.a))
			}
			return splitRes("s", bytes.Fields(x.a))
		}},
		{"FieldsFunc", func(w bool, x *byteArgs) ([][]byte, []string) {
			c := &fbCounter{}
			var r [][]byte
			if w {
				r = iastprop.BytesFieldsFunc(x.a, c.comma)
			} else {
				r = bytes.FieldsFunc(x.a, c.comma)
			}
			res, sc := splitRes("s", r)
			return res, append(sc, "calls="+strconv.Itoa(c.n))
		}},
		{"Trim", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return one(iastprop.BytesTrim(x.a, x.cut)), nil
			}
			return one(bytes.Trim(x.a, x.cut)), nil
		}},
		{"TrimSpace", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return one(iastprop.BytesTrimSpace(x.a)), nil
			}
			return one(bytes.TrimSpace(x.a)), nil
		}},
		{"TrimLeft", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return one(iastprop.BytesTrimLeft(x.a, x.cut)), nil
			}
			return one(bytes.TrimLeft(x.a, x.cut)), nil
		}},
		{"TrimRight", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return one(iastprop.BytesTrimRight(x.a, x.cut)), nil
			}
			return one(bytes.TrimRight(x.a, x.cut)), nil
		}},
		{"TrimPrefix", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return one(iastprop.BytesTrimPrefix(x.a, x.b)), nil
			}
			return one(bytes.TrimPrefix(x.a, x.b)), nil
		}},
		{"TrimSuffix", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return one(iastprop.BytesTrimSuffix(x.a, x.b)), nil
			}
			return one(bytes.TrimSuffix(x.a, x.b)), nil
		}},
		{"TrimFunc", func(w bool, x *byteArgs) ([][]byte, []string) {
			c := &fbCounter{}
			var r []byte
			if w {
				r = iastprop.BytesTrimFunc(x.a, c.space)
			} else {
				r = bytes.TrimFunc(x.a, c.space)
			}
			return one(r), []string{"calls=" + strconv.Itoa(c.n)}
		}},
		{"TrimLeftFunc", func(w bool, x *byteArgs) ([][]byte, []string) {
			c := &fbCounter{}
			var r []byte
			if w {
				r = iastprop.BytesTrimLeftFunc(x.a, c.space)
			} else {
				r = bytes.TrimLeftFunc(x.a, c.space)
			}
			return one(r), []string{"calls=" + strconv.Itoa(c.n)}
		}},
		{"TrimRightFunc", func(w bool, x *byteArgs) ([][]byte, []string) {
			c := &fbCounter{}
			var r []byte
			if w {
				r = iastprop.BytesTrimRightFunc(x.a, c.space)
			} else {
				r = bytes.TrimRightFunc(x.a, c.space)
			}
			return one(r), []string{"calls=" + strconv.Itoa(c.n)}
		}},
		{"Replace", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return one(iastprop.BytesReplace(x.a, x.b, x.c, x.n)), nil
			}
			return one(bytes.Replace(x.a, x.b, x.c, x.n)), nil
		}},
		{"ReplaceAll", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return one(iastprop.BytesReplaceAll(x.a, x.b, x.c)), nil
			}
			return one(bytes.ReplaceAll(x.a, x.b, x.c)), nil
		}},
		{"ToLower", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return one(iastprop.BytesToLower(x.a)), nil
			}
			return one(bytes.ToLower(x.a)), nil
		}},
		{"ToUpper", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return one(iastprop.BytesToUpper(x.a)), nil
			}
			return one(bytes.ToUpper(x.a)), nil
		}},
		{"ToTitle", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return one(iastprop.BytesToTitle(x.a)), nil
			}
			return one(bytes.ToTitle(x.a)), nil
		}},
		{"Map", func(w bool, x *byteArgs) ([][]byte, []string) {
			c := &fbCounter{}
			var r []byte
			if w {
				r = iastprop.BytesMap(c.mapr, x.a)
			} else {
				r = bytes.Map(c.mapr, x.a)
			}
			return one(r), []string{"calls=" + strconv.Itoa(c.n)}
		}},
		{"ToValidUTF8", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return one(iastprop.BytesToValidUTF8(x.a, x.c)), nil
			}
			return one(bytes.ToValidUTF8(x.a, x.c)), nil
		}},
		// Byte slicing operator wrappers (aliasing-critical).
		{"SliceAll", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return one(iastprop.BytesSliceAll(x.a)), nil
			}
			return one(x.a[:]), nil
		}},
		{"SliceLow", func(w bool, x *byteArgs) ([][]byte, []string) {
			lo := x.n
			if w {
				return one(iastprop.BytesSliceLow(x.a, lo)), nil
			}
			return one(x.a[lo:]), nil
		}},
		{"SliceHigh", func(w bool, x *byteArgs) ([][]byte, []string) {
			hi := x.n + 1
			if w {
				return one(iastprop.BytesSliceHigh(x.a, hi)), nil
			}
			return one(x.a[:hi]), nil
		}},
		{"SliceBounds", func(w bool, x *byteArgs) ([][]byte, []string) {
			lo, hi := x.n/2, x.n+1
			if w {
				return one(iastprop.BytesSliceBounds(x.a, lo, hi)), nil
			}
			return one(x.a[lo:hi]), nil
		}},
		{"SliceFull", func(w bool, x *byteArgs) ([][]byte, []string) {
			lo, hi, mx := x.n/2, x.n, x.n+2
			if w {
				return one(iastprop.BytesSliceFull(x.a, lo, hi, mx)), nil
			}
			return one(x.a[lo:hi:mx]), nil
		}},
		{"SliceFullZero", func(w bool, x *byteArgs) ([][]byte, []string) {
			hi, mx := x.n, x.n+1
			if w {
				return one(iastprop.BytesSliceFullZero(x.a, hi, mx)), nil
			}
			return one(x.a[:hi:mx]), nil
		}},
		{"BytesToString", func(w bool, x *byteArgs) ([][]byte, []string) {
			if w {
				return nil, []string{iastprop.BytesToString(x.a)}
			}
			return nil, []string{string(x.a)}
		}},
	}
}

// --- random generation ---------------------------------------------------------

var fbAtoms = []string{"a", "b", "A", "Z", "x", ",", ", ", " ", "\t", "\n", "é", "ß", "İ", "ǅ", "ﬀ", "\xff", "\xc3", "\xe2\x82", "!", "--", "ab", "\u00a0", "\u2028", "Σ", "ς", "日本", "0", "=", "&", "'"}

func genB(r *rand.Rand, maxAtoms int) []byte {
	switch r.IntN(12) {
	case 0:
		return nil
	case 1:
		return []byte{}
	}
	var sb strings.Builder
	n := r.IntN(maxAtoms + 1)
	for i := 0; i < n; i++ {
		sb.WriteString(fbAtoms[r.IntN(len(fbAtoms))])
	}
	s := sb.String()
	// Place in a larger backing array at a random offset and with spare cap so
	// alias offsets and capacity limits are non-trivial.
	pre, post := r.IntN(4), r.IntN(6)
	back := make([]byte, pre+len(s)+post)
	for i := range back {
		back[i] = '~'
	}
	copy(back[pre:], s)
	if r.IntN(3) == 0 {
		return back[pre : pre+len(s) : pre+len(s)]
	}
	return back[pre : pre+len(s)]
}

func genSep(r *rand.Rand) []byte {
	switch r.IntN(8) {
	case 0:
		return nil
	case 1:
		return []byte{}
	}
	return genB(r, 2)
}

func genCount(r *rand.Rand, forRepeat bool, a []byte) int {
	switch r.IntN(10) {
	case 0:
		return -1
	case 1:
		return 0
	case 2:
		if forRepeat && len(a) > 0 {
			return math.MaxInt/len(a) + 1 // overflow panic
		}
		return 40
	case 3:
		return -r.IntN(3) - 2
	}
	return r.IntN(6)
}

// --- the byte differential test -----------------------------------------------

func TestFidelityBytesDifferential(t *testing.T) {
	fbConfig(t)
	iters := fbIterations()
	cases := byteCases()
	failures := 0
	checked := 0
	taintedResults := map[string]int{}
	for _, mode := range []fbMode{fbInactive, fbActiveClean, fbTainted, fbForeign} {
		env := &fbEnv{t: t}
		rng := rand.New(rand.NewPCG(uint64(mode)+1, 99))
		taintedSeen, taintedWanted := 0, 0
		for it := 0; it < iters; it++ {
			for _, bc := range cases {
				// Fresh scopes per case so per-request source/root budgets never
				// saturate and tainted modes really exercise tainted inputs.
				env.startMode(mode)
				raw := byteArgs{a: genB(rng, 12), b: genSep(rng), c: genSep(rng), cut: string(genSep(rng))}
				if bc.name == "Repeat" {
					raw.n = genCount(rng, true, raw.a)
				} else if strings.HasPrefix(bc.name, "Slice") {
					raw.n = rng.IntN(len(raw.a) + 3)
				} else {
					raw.n = genCount(rng, false, raw.a)
				}
				ne := rng.IntN(20)
				if rng.IntN(5) == 0 {
					ne = 0
				}
				for i := 0; i < ne; i++ {
					raw.elems = append(raw.elems, genB(rng, 3))
				}
				if rng.IntN(15) == 0 {
					raw.elems = nil
				}
				// Build the (possibly tainted) args, shared by std and wrapper.
				x := byteArgs{cut: raw.cut, n: raw.n}
				x.a = env.taintB(mode, 0, raw.a)
				x.b = env.taintB(mode, 1, raw.b)
				x.c = env.taintB(mode, 2, raw.c)
				for i, e := range raw.elems {
					x.elems = append(x.elems, env.taintB(mode, 3+i, e))
				}
				if x.elems == nil && raw.elems != nil {
					x.elems = [][]byte{}
				}
				if len(x.a) > 1 && (mode == fbTainted || mode == fbForeign) {
					taintedWanted++
					if taint.IsTaintedBytes(x.a) {
						taintedSeen++
					}
				}
				// Aliasing/result check on shared inputs.
				snap := [][]byte{cloneCap(x.a), cloneCap(x.b), cloneCap(x.c)}
				std := fbCapture(func() []string { r, s := bc.run(false, &x); return descAll(r, s, &x) })
				wr := fbCapture(func() []string {
					r, s := bc.run(true, &x)
					for _, v := range r {
						if len(v) > 0 && taint.IsTaintedBytes(v) {
							taintedResults[bc.name]++
						}
					}
					return descAll(r, s, &x)
				})
				checked++
				if std.panicked != wr.panicked || std.pv != wr.pv || !reflect.DeepEqual(std.vals, wr.vals) {
					failures++
					if failures <= 30 {
						t.Errorf("[%v] %s mismatch a=%q b=%q c=%q cut=%q n=%d elems=%q\n std=%v %q %q\n wrp=%v %q %q",
							mode, bc.name, x.a, x.b, x.c, x.cut, x.n, x.elems, std.panicked, std.pv, std.vals, wr.panicked, wr.pv, wr.vals)
					}
				}
				for i, in := range [][]byte{x.a, x.b, x.c} {
					if !bytes.Equal(fullView(in), fullView(snap[i])) {
						failures++
						t.Errorf("[%v] %s mutated input %d", mode, bc.name, i)
					}
				}
				// Mutation-through-result check on independent identical inputs.
				mutA := mutationRun(env, mode, &raw, bc, false)
				mutB := mutationRun(env, mode, &raw, bc, true)
				if !reflect.DeepEqual(mutA, mutB) {
					failures++
					if failures <= 30 {
						t.Errorf("[%v] %s mutation-through-result mismatch a=%q\n std=%q\n wrp=%q", mode, bc.name, raw.a, mutA, mutB)
					}
				}
				env.finish()
			}
		}
		if mode == fbTainted || mode == fbForeign {
			if taintedSeen == 0 || taintedSeen < taintedWanted*9/10 {
				t.Fatalf("[%v] only %d/%d primary inputs were tainted: harness would pass vacuously", mode, taintedSeen, taintedWanted)
			}
			t.Logf("[%v] tainted primary inputs (len>=2): %d/%d", mode, taintedSeen, taintedWanted)
		}
	}
	t.Logf("wrapper results observed tainted per op: %v", taintedResults)
	t.Logf("byte differential: %d comparisons, %d failures", checked, failures)
}

// mutationRun performs the op on a fresh identical copy of the inputs, then
// writes through each result (index write and append) and reports the full
// backing content of each input plus each result.
func mutationRun(env *fbEnv, mode fbMode, raw *byteArgs, bc byteCase, wrap bool) []string {
	x := byteArgs{cut: raw.cut, n: raw.n}
	x.a = env.taintB(mode, 0, cloneCap(raw.a))
	x.b = env.taintB(mode, 1, cloneCap(raw.b))
	x.c = env.taintB(mode, 2, cloneCap(raw.c))
	for i, e := range raw.elems {
		x.elems = append(x.elems, env.taintB(mode, 3+i, cloneCap(e)))
	}
	o := fbCapture(func() []string {
		res, _ := bc.run(wrap, &x)
		var out []string
		for i, r := range res {
			if len(r) > 0 {
				r[0] ^= 0x20
			}
			if cap(r) > len(r) {
				_ = append(r, byte('0'+i%10))
			}
			out = append(out, fmt.Sprintf("r%d=%q", i, r))
		}
		return out
	})
	out := append([]string{fmt.Sprint(o.panicked, o.pv)}, o.vals...)
	for i, in := range [][]byte{x.a, x.b, x.c} {
		out = append(out, fmt.Sprintf("in%d=%q", i, fullView(in)))
	}
	for i, in := range x.elems {
		out = append(out, fmt.Sprintf("el%d=%q", i, fullView(in)))
	}
	return out
}

// --- writer differential -------------------------------------------------------

type bufState struct {
	Len, Cap, Avail, BytesCap, AvailBufCap int
	Content                                string
	UnreadByte, UnreadRune                 string
}

func errStr(err error) string {
	if err == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%T:%v", err, err)
}

func bufferState(b *bytes.Buffer) bufState {
	c1, c2 := *b, *b // value copies share backing; Unread* only moves off.
	return bufState{
		Len: b.Len(), Cap: b.Cap(), Avail: b.Available(), BytesCap: cap(b.Bytes()), AvailBufCap: cap(b.AvailableBuffer()),
		Content: string(b.Bytes()), UnreadByte: errStr(c1.UnreadByte()), UnreadRune: errStr(c2.UnreadRune()),
	}
}

type buildState struct {
	Len, Cap int
	Content  string
}

func builderState(b *strings.Builder) buildState {
	return buildState{Len: b.Len(), Cap: b.Cap(), Content: b.String()}
}

func genWriteBytes(r *rand.Rand, env *fbEnv, mode fbMode, i int) []byte {
	v := genB(r, 6)
	if r.IntN(10) == 0 && len(v) > 0 {
		v = bytes.Repeat(v, 200) // cross growth thresholds / MaxRootBytes paths
	}
	return env.taintB(mode, i, v)
}

func genWriteString(r *rand.Rand, env *fbEnv, mode fbMode, i int) string {
	return env.taintS(mode, i, string(genB(r, 6)))
}

var runesPool = []rune{'a', 'Z', 0, 0x7f, 0x80, 'é', '日', 0x10FFFF, 0x110000, -1, 0xD800, utf8Err, '😀'}

type bufOp struct {
	name string
	// apply performs the op on b, via wrapper when wrap is set. Args are pre-
	// generated so both sides see the exact same value/backing.
	apply func(b *bytes.Buffer, wrap bool) string
}

func genBufOp(r *rand.Rand, env *fbEnv, mode fbMode, k int, self *bytes.Buffer) bufOp {
	switch r.IntN(17) {
	case 0, 1:
		v := genWriteBytes(r, env, mode, k)
		return bufOp{"Write", func(b *bytes.Buffer, w bool) string {
			var n int
			var err error
			if w {
				n, err = iastprop.BufferWrite(b, v)
			} else {
				n, err = b.Write(v)
			}
			return fmt.Sprint(n, errStr(err))
		}}
	case 2, 3:
		v := genWriteString(r, env, mode, k)
		return bufOp{"WriteString", func(b *bytes.Buffer, w bool) string {
			var n int
			var err error
			if w {
				n, err = iastprop.BufferWriteString(b, v)
			} else {
				n, err = b.WriteString(v)
			}
			return fmt.Sprint(n, errStr(err))
		}}
	case 4:
		c := byte(r.IntN(256))
		return bufOp{"WriteByte", func(b *bytes.Buffer, w bool) string {
			if w {
				return errStr(iastprop.BufferWriteByte(b, c))
			}
			return errStr(b.WriteByte(c))
		}}
	case 5:
		c := runesPool[r.IntN(len(runesPool))]
		return bufOp{"WriteRune", func(b *bytes.Buffer, w bool) string {
			var n int
			var err error
			if w {
				n, err = iastprop.BufferWriteRune(b, c)
			} else {
				n, err = b.WriteRune(c)
			}
			return fmt.Sprint(n, errStr(err))
		}}
	case 6:
		n := r.IntN(80) - 5
		return bufOp{"Grow", func(b *bytes.Buffer, w bool) string {
			if w {
				iastprop.BufferGrow(b, n)
			} else {
				b.Grow(n)
			}
			return ""
		}}
	case 7:
		return bufOp{"Reset", func(b *bytes.Buffer, w bool) string {
			if w {
				iastprop.BufferReset(b)
			} else {
				b.Reset()
			}
			return ""
		}}
	case 8:
		n := r.IntN(12) - 2
		return bufOp{"Truncate", func(b *bytes.Buffer, w bool) string {
			if w {
				iastprop.BufferTruncate(b, n)
			} else {
				b.Truncate(n)
			}
			return ""
		}}
	case 9, 10:
		return bufOp{"String", func(b *bytes.Buffer, w bool) string {
			if w {
				return iastprop.BufferString(b)
			}
			return b.String()
		}}
	case 11:
		n := r.IntN(5)
		return bufOp{"Next(native)", func(b *bytes.Buffer, _ bool) string { return string(b.Next(n)) }}
	case 12:
		return bufOp{"ReadRune(native)", func(b *bytes.Buffer, _ bool) string {
			c, s, err := b.ReadRune()
			return fmt.Sprint(c, s, errStr(err))
		}}
	case 13:
		return bufOp{"ReadByte(native)", func(b *bytes.Buffer, _ bool) string {
			c, err := b.ReadByte()
			return fmt.Sprint(c, errStr(err))
		}}
	case 14:
		// Self-aliasing write: buf.Write(buf.Bytes()[i:j]).
		i := r.IntN(4)
		return bufOp{"WriteSelf", func(b *bytes.Buffer, w bool) string {
			v := b.Bytes()
			if i < len(v) {
				v = v[i:]
			}
			var n int
			var err error
			if w {
				n, err = iastprop.BufferWrite(b, v)
			} else {
				n, err = b.Write(v)
			}
			return fmt.Sprint(n, errStr(err))
		}}
	case 15:
		return bufOp{"AvailableBufferAppend(native)", func(b *bytes.Buffer, w bool) string {
			p := append(b.AvailableBuffer(), "zz"...)
			var n int
			var err error
			if w {
				n, err = iastprop.BufferWrite(b, p)
			} else {
				n, err = b.Write(p)
			}
			return fmt.Sprint(n, errStr(err))
		}}
	default:
		return bufOp{"UnreadRune(native)", func(b *bytes.Buffer, _ bool) string { return errStr(b.UnreadRune()) }}
	}
}

type buildOp struct {
	name  string
	apply func(b *strings.Builder, wrap bool) string
}

func genBuildOp(r *rand.Rand, env *fbEnv, mode fbMode, k int) buildOp {
	switch r.IntN(10) {
	case 0, 1:
		v := genWriteBytes(r, env, mode, k)
		return buildOp{"Write", func(b *strings.Builder, w bool) string {
			var n int
			var err error
			if w {
				n, err = iastprop.BuilderWrite(b, v)
			} else {
				n, err = b.Write(v)
			}
			return fmt.Sprint(n, errStr(err))
		}}
	case 2, 3:
		v := genWriteString(r, env, mode, k)
		return buildOp{"WriteString", func(b *strings.Builder, w bool) string {
			var n int
			var err error
			if w {
				n, err = iastprop.BuilderWriteString(b, v)
			} else {
				n, err = b.WriteString(v)
			}
			return fmt.Sprint(n, errStr(err))
		}}
	case 4:
		c := byte(r.IntN(256))
		return buildOp{"WriteByte", func(b *strings.Builder, w bool) string {
			if w {
				return errStr(iastprop.BuilderWriteByte(b, c))
			}
			return errStr(b.WriteByte(c))
		}}
	case 5:
		c := runesPool[r.IntN(len(runesPool))]
		return buildOp{"WriteRune", func(b *strings.Builder, w bool) string {
			var n int
			var err error
			if w {
				n, err = iastprop.BuilderWriteRune(b, c)
			} else {
				n, err = b.WriteRune(c)
			}
			return fmt.Sprint(n, errStr(err))
		}}
	case 6:
		n := r.IntN(80) - 5
		return buildOp{"Grow", func(b *strings.Builder, w bool) string {
			if w {
				iastprop.BuilderGrow(b, n)
			} else {
				b.Grow(n)
			}
			return ""
		}}
	case 7:
		return buildOp{"Reset", func(b *strings.Builder, w bool) string {
			if w {
				iastprop.BuilderReset(b)
			} else {
				b.Reset()
			}
			return ""
		}}
	default:
		return buildOp{"String", func(b *strings.Builder, w bool) string {
			var s string
			if w {
				s = iastprop.BuilderString(b)
			} else {
				s = b.String()
			}
			// Aliasing: native String() aliases the builder buffer base.
			native := b.String()
			same := len(s) == 0 || unsafe.StringData(s) == unsafe.StringData(native)
			return fmt.Sprintf("%q aliasesBuf=%v", s, same)
		}}
	}
}

func TestFidelityWritersDifferential(t *testing.T) {
	fbConfig(t)
	iters := fbIterations()
	failures, checked := 0, 0
	aliasDiverge := map[fbMode]int{}
	bufTaintedStrings := 0
	for _, mode := range []fbMode{fbInactive, fbActiveClean, fbTainted, fbForeign} {
		env := &fbEnv{t: t}
		rng := rand.New(rand.NewPCG(uint64(mode)+7, 3))
		for it := 0; it < iters; it++ {
			env.startMode(mode)
			// bytes.Buffer, optionally initialized via NewBuffer/NewBufferString.
			var A, B *bytes.Buffer
			switch rng.IntN(3) {
			case 0:
				A, B = new(bytes.Buffer), new(bytes.Buffer)
			case 1:
				seed := genB(rng, 5)
				A, B = bytes.NewBuffer(env.taintB(mode, 98, cloneCap(seed))), bytes.NewBuffer(env.taintB(mode, 99, cloneCap(seed)))
			default:
				s := string(genB(rng, 5))
				A, B = bytes.NewBufferString(s), bytes.NewBufferString(s)
			}
			var trace []string
			for k := 0; k < 12; k++ {
				op := genBufOp(rng, env, mode, k, A)
				ra := fbCapture(func() []string { return []string{op.apply(A, false)} })
				rb := fbCapture(func() []string { return []string{op.apply(B, true)} })
				if op.name == "String" && len(rb.vals) == 1 && len(rb.vals[0]) > 0 && taint.IsTaintedString(rb.vals[0]) {
					bufTaintedStrings++
				}
				sa, sb := bufferState(A), bufferState(B)
				trace = append(trace, op.name)
				checked++
				if ra.panicked != rb.panicked || ra.pv != rb.pv || !reflect.DeepEqual(ra.vals, rb.vals) || sa != sb {
					failures++
					if failures <= 30 {
						t.Errorf("[%v] Buffer op %v diverged\n std=%v %q %q %+v\n wrp=%v %q %q %+v", mode, trace, ra.panicked, ra.pv, ra.vals, sa, rb.panicked, rb.pv, rb.vals, sb)
					}
					break
				}
			}
			// strings.Builder.
			var C, D strings.Builder
			trace = nil
			for k := 0; k < 12; k++ {
				op := genBuildOp(rng, env, mode, k)
				rc := fbCapture(func() []string { return []string{op.apply(&C, false)} })
				rd := fbCapture(func() []string { return []string{op.apply(&D, true)} })
				sc, sd := builderState(&C), builderState(&D)
				trace = append(trace, op.name)
				checked++
				if op.name == "String" && len(rc.vals) == 1 && len(rd.vals) == 1 && rc.vals[0] != rd.vals[0] &&
					strings.TrimSuffix(rc.vals[0], " aliasesBuf=true") == strings.TrimSuffix(rd.vals[0], " aliasesBuf=false") {
					aliasDiverge[mode]++
					continue // content equal; identity-only divergence recorded separately
				}
				if rc.panicked != rd.panicked || rc.pv != rd.pv || !reflect.DeepEqual(rc.vals, rd.vals) || sc != sd {
					failures++
					if failures <= 30 {
						t.Errorf("[%v] Builder op %v diverged\n std=%v %q %q %+v\n wrp=%v %q %q %+v", mode, trace, rc.panicked, rc.pv, rc.vals, sc, rd.panicked, rd.pv, rd.vals, sd)
					}
					break
				}
			}
			env.finish()
		}
	}
	for _, m := range []fbMode{fbInactive, fbActiveClean, fbTainted, fbForeign} {
		t.Logf("[%v] Builder.String identity divergence (clone instead of alias): %d", m, aliasDiverge[m])
	}
	t.Logf("Buffer.String wrapper results observed tainted: %d", bufTaintedStrings)
	t.Logf("writer differential: %d comparisons, %d failures", checked, failures)
}

// Edge cases: nil receivers, copied builders, Grow/Truncate panics.
func TestFidelityWriterEdgeCases(t *testing.T) {
	fbConfig(t)
	for _, mode := range []fbMode{fbInactive, fbTainted} {
		env := &fbEnv{t: t}
		if mode == fbTainted {
			env.begin(1)
		}
		tv := env.taintB(mode, 0, []byte("attack-payload"))
		ts := env.taintS(mode, 1, "attack-payload")
		type pair struct {
			name     string
			std, wrp func() []string
		}
		var nb *bytes.Buffer
		var ns *strings.Builder
		copied := func() *strings.Builder {
			var b strings.Builder
			b.WriteString("seed")
			c := b //nolint
			return &c
		}
		pairs := []pair{
			{"nil Buffer.String", func() []string { return []string{nb.String()} }, func() []string { return []string{iastprop.BufferString(nb)} }},
			{"nil Buffer.Write", func() []string { nb.Write(tv); return nil }, func() []string { iastprop.BufferWrite(nb, tv); return nil }},
			{"nil Buffer.WriteString", func() []string { nb.WriteString(ts); return nil }, func() []string { iastprop.BufferWriteString(nb, ts); return nil }},
			{"nil Buffer.WriteByte", func() []string { nb.WriteByte(1); return nil }, func() []string { iastprop.BufferWriteByte(nb, 1); return nil }},
			{"nil Buffer.WriteRune", func() []string { nb.WriteRune('é'); return nil }, func() []string { iastprop.BufferWriteRune(nb, 'é'); return nil }},
			{"nil Buffer.Grow", func() []string { nb.Grow(3); return nil }, func() []string { iastprop.BufferGrow(nb, 3); return nil }},
			{"nil Buffer.Reset", func() []string { nb.Reset(); return nil }, func() []string { iastprop.BufferReset(nb); return nil }},
			{"nil Buffer.Truncate0", func() []string { nb.Truncate(0); return nil }, func() []string { iastprop.BufferTruncate(nb, 0); return nil }},
			{"nil Builder.String", func() []string { return []string{ns.String()} }, func() []string { return []string{iastprop.BuilderString(ns)} }},
			{"nil Builder.Write", func() []string { ns.Write(tv); return nil }, func() []string { iastprop.BuilderWrite(ns, tv); return nil }},
			{"nil Builder.WriteString", func() []string { ns.WriteString(ts); return nil }, func() []string { iastprop.BuilderWriteString(ns, ts); return nil }},
			{"nil Builder.WriteByte", func() []string { ns.WriteByte(1); return nil }, func() []string { iastprop.BuilderWriteByte(ns, 1); return nil }},
			{"nil Builder.WriteRune", func() []string { ns.WriteRune(1); return nil }, func() []string { iastprop.BuilderWriteRune(ns, 1); return nil }},
			{"nil Builder.Grow", func() []string { ns.Grow(1); return nil }, func() []string { iastprop.BuilderGrow(ns, 1); return nil }},
			{"nil Builder.Reset", func() []string { ns.Reset(); return nil }, func() []string { iastprop.BuilderReset(ns); return nil }},
			{"copied Builder.WriteString", func() []string { copied().WriteString(ts); return nil }, func() []string { iastprop.BuilderWriteString(copied(), ts); return nil }},
			{"copied Builder.Write", func() []string { copied().Write(tv); return nil }, func() []string { iastprop.BuilderWrite(copied(), tv); return nil }},
			{"copied Builder.Grow", func() []string { copied().Grow(100); return nil }, func() []string { iastprop.BuilderGrow(copied(), 100); return nil }},
			{"copied Builder.String", func() []string { return []string{copied().String()} }, func() []string { return []string{iastprop.BuilderString(copied())} }},
			{"copied Builder.Reset+Write", func() []string { c := copied(); c.Reset(); c.WriteString(ts); return []string{c.String()} }, func() []string {
				c := copied()
				iastprop.BuilderReset(c)
				iastprop.BuilderWriteString(c, ts)
				return []string{iastprop.BuilderString(c)}
			}},
			{"Builder.Grow(-1)", func() []string { var b strings.Builder; b.Grow(-1); return nil }, func() []string { var b strings.Builder; iastprop.BuilderGrow(&b, -1); return nil }},
			{"Buffer.Grow(-1)", func() []string { var b bytes.Buffer; b.Grow(-1); return nil }, func() []string { var b bytes.Buffer; iastprop.BufferGrow(&b, -1); return nil }},
			{"Buffer.Truncate(-1)", func() []string { b := bytes.NewBufferString("abc"); b.Truncate(-1); return nil }, func() []string { b := bytes.NewBufferString("abc"); iastprop.BufferTruncate(b, -1); return nil }},
			{"Buffer.Truncate(>len)", func() []string { b := bytes.NewBufferString("abc"); b.Truncate(9); return nil }, func() []string { b := bytes.NewBufferString("abc"); iastprop.BufferTruncate(b, 9); return nil }},
			{"Buffer.ReadRune+String+UnreadRune", func() []string {
				b := bytes.NewBufferString("éa")
				b.ReadRune()
				s := b.String()
				return []string{s, errStr(b.UnreadRune())}
			}, func() []string {
				b := bytes.NewBufferString("éa")
				b.ReadRune()
				s := iastprop.BufferString(b)
				return []string{s, errStr(b.UnreadRune())}
			}},
			{"Buffer.ReadByte+Write+UnreadByte", func() []string {
				b := bytes.NewBuffer(cloneCap(tv))
				b.ReadByte()
				b.Write(tv)
				return []string{b.String(), errStr(b.UnreadByte())}
			}, func() []string {
				b := bytes.NewBuffer(cloneCap(tv))
				b.ReadByte()
				iastprop.BufferWrite(b, tv)
				return []string{iastprop.BufferString(b), errStr(b.UnreadByte())}
			}},
			{"Buffer.ReadByte+Truncate+UnreadByte", func() []string {
				b := bytes.NewBufferString("abcd")
				b.ReadByte()
				b.Truncate(2)
				return []string{b.String(), errStr(b.UnreadByte())}
			}, func() []string {
				b := bytes.NewBufferString("abcd")
				b.ReadByte()
				iastprop.BufferTruncate(b, 2)
				return []string{iastprop.BufferString(b), errStr(b.UnreadByte())}
			}},
			{"Buffer.ReadByte+Grow+UnreadByte", func() []string {
				b := bytes.NewBufferString("abcd")
				b.ReadByte()
				b.Grow(100)
				return []string{b.String(), errStr(b.UnreadByte())}
			}, func() []string {
				b := bytes.NewBufferString("abcd")
				b.ReadByte()
				iastprop.BufferGrow(b, 100)
				return []string{iastprop.BufferString(b), errStr(b.UnreadByte())}
			}},
		}
		for _, p := range pairs {
			a := fbCapture(p.std)
			b := fbCapture(p.wrp)
			if a.panicked != b.panicked || a.pv != b.pv || !reflect.DeepEqual(a.vals, b.vals) {
				t.Errorf("[%v] %s: std=%v %q %q wrp=%v %q %q", mode, p.name, a.panicked, a.pv, a.vals, b.panicked, b.pv, b.vals)
			} else {
				t.Logf("[%v] %s: ok (panicked=%v %s)", mode, p.name, a.panicked, a.pv)
			}
		}
		env.finish()
	}
}

// Builder.String identity: native String() aliases the builder's buffer and is
// allocation-free; the wrapper clones when the builder carries taint state.
func TestFidelityBuilderStringIdentityAndAllocs(t *testing.T) {
	fbConfig(t)
	env := &fbEnv{t: t}
	env.begin(1)
	defer env.finish()
	payload := env.taintS(fbTainted, 0, strings.Repeat("attack", 1000)) // 6000 bytes
	var b strings.Builder
	iastprop.BuilderWriteString(&b, payload)
	native := b.String()
	wrapped := iastprop.BuilderString(&b)
	t.Logf("native ptr==buf: true; wrapped ptr==native ptr: %v; wrapped tainted=%v native tainted=%v",
		unsafe.StringData(native) == unsafe.StringData(wrapped), taint.IsTaintedString(wrapped), taint.IsTaintedString(native))
	nAllocs := testing.AllocsPerRun(50, func() { _ = b.String() })
	wAllocs := testing.AllocsPerRun(50, func() { _ = iastprop.BuilderString(&b) })
	t.Logf("allocs/op for String() on a 6000-byte tainted builder: native=%.1f wrapped=%.1f", nAllocs, wAllocs)
}
