package zzdiffbytes

import (
	"bytes"
	"math/rand/v2"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/taint"
)

var fnNames = []string{"Clone", "Join", "Repeat", "Cut", "CutPrefix", "CutSuffix", "Split", "SplitN", "SplitAfter", "SplitAfterN", "Fields", "FieldsFunc", "Trim", "TrimSpace", "TrimLeft", "TrimRight", "TrimPrefix", "TrimSuffix", "TrimFunc", "TrimLeftFunc", "TrimRightFunc", "Replace", "ReplaceAll", "ToLower", "ToUpper", "ToTitle", "Map", "ToValidUTF8", "slice2", "slice3", "string()"}

func (e *env) pickSep(x []byte) []byte {
	switch e.rng.IntN(8) {
	case 0:
		return nil
	case 1:
		return []byte{}
	case 2:
		return []byte(",")
	case 3:
		return []byte("a")
	case 4:
		return []byte("é")
	case 5:
		if len(x) > 0 {
			lo := e.rng.IntN(len(x))
			hi := lo + 1 + e.rng.IntN(min(3, len(x)-lo))
			return x[lo:hi]
		}
		return []byte("\n")
	case 6:
		return e.pickBytes()
	default:
		return []byte(e.randText(2))
	}
}

func (e *env) randArgs() FnArgs {
	a := FnArgs{Fn: e.rng.IntN(FnCount), Pred: e.rng.IntN(8)}
	a.X = e.pickBytes()
	a.Y = e.pickSep(a.X)
	a.Z = e.pickBytes()
	if a.Fn == 27 && e.rng.IntN(2) == 0 {
		a.Y = []byte("\uFFFD")
	}
	if a.Fn == 1 {
		n := e.rng.IntN(20)
		if e.rng.IntN(6) == 0 {
			a.Parts = nil
		} else {
			a.Parts = make([][]byte, n)
			for i := range a.Parts {
				a.Parts[i] = e.pickBytes()
			}
		}
	}
	a.Cut = []string{"", " ,", "a\xff", "é", "\n\t ", "abc,"}[e.rng.IntN(6)]
	a.N = e.rng.IntN(9) - 3
	switch e.rng.IntN(12) {
	case 0:
		a.N = 40
	case 1:
		if a.Fn == 2 {
			a.N = int(^uint(0)>>1) / 3
		}
	}
	if a.Fn == 28 || a.Fn == 29 {
		c := cap(a.X) + 2
		a.N = e.rng.IntN(c+1) | e.rng.IntN(c+1)<<8 | e.rng.IntN(c+1)<<16
	}
	return a
}

type inputRef struct {
	v     []byte
	cells []cell
}

func (e *env) inputs(a FnArgs) []inputRef {
	refs := []inputRef{{a.X, e.cellsOfBytes(a.X)}, {a.Y, e.cellsOfBytes(a.Y)}, {a.Z, e.cellsOfBytes(a.Z)}}
	for _, p := range a.Parts {
		refs = append(refs, inputRef{p, e.cellsOfBytes(p)})
	}
	return refs
}

func aliasClass(v []byte, refs []inputRef) (int, int) {
	for i, r := range refs {
		if off := AliasOff(v, r.v[:cap(r.v)]); off >= 0 {
			return i, off
		}
	}
	return -1, -1
}

func encSlice(dst, v []byte, refs []inputRef) []byte {
	dst = appendBytes(dst, v)
	i, off := aliasClass(v, refs)
	dst = appendInt(dst, int64(i))
	return appendInt(dst, int64(off))
}

func (r *FnRes) enc(refs []inputRef) []byte {
	var dst []byte
	if r.HasA {
		dst = encSlice(append(dst, 'A'), r.A, refs)
	}
	if r.HasB {
		dst = encSlice(append(dst, 'B'), r.B, refs)
	}
	if r.HasL {
		if r.List == nil {
			dst = append(dst, 'n')
		}
		dst = appendInt(append(dst, 'L'), int64(len(r.List)))
		dst = appendInt(dst, int64(cap(r.List)))
		for _, v := range r.List {
			dst = encSlice(dst, v, refs)
		}
	}
	if r.Ok {
		dst = append(dst, 'o')
	}
	dst = appendString(dst, r.S)
	dst = appendString(dst, r.Panic)
	for _, t := range r.Trace {
		dst = appendInt(dst, int64(t))
	}
	return dst
}

func (e *env) checkMembership(what string, v []byte, refs []inputRef) {
	if !e.active {
		return
	}
	allowed := map[string]bool{}
	anyTaint := false
	for _, r := range refs {
		for _, c := range r.cells {
			if c >= 0 {
				allowed[e.sources[c]] = true
				anyTaint = true
			}
		}
	}
	seen := false
	taint.VisitBytes(v, func(r taint.Range) bool {
		seen = true
		if int(r.Start+r.Length) > len(v) {
			e.fail("%s: range [%d,+%d) exceeds length %d", what, r.Start, r.Length, len(v))
			return false
		}
		if !allowed[r.Source.Value] {
			e.fail("%s: FALSE TAINT source %q not among inputs (anyTaint=%v)", what, r.Source.Value, anyTaint)
			return false
		}
		return true
	})
	if anyTaint && len(v) >= 2 {
		e.stats[what+".expected"]++
		if !seen {
			e.stats[what+".lost"]++
		}
	}
}

func (e *env) checkFnSlice(what string, fn int, v []byte, refs []inputRef, a FnArgs) {
	if len(v) == 0 {
		return
	}
	if k, off := aliasClass(v, refs); k >= 0 {
		cells := refs[k].cells
		exp := clean(len(v))
		for i := range exp {
			if off+i < len(cells) {
				exp[i] = cells[off+i]
			} else {
				exp[i] = unknownCell // reslice into capacity of the input's root
			}
		}
		e.checkBytes(what+".window", v, exp)
		return
	}
	switch fn {
	case 0, 30:
		e.checkBytes(what, v, refs[0].cells)
	case 1:
		if len(a.Parts) > 16 {
			// Documented coarse fallback (bytes_exact.go:17-18).
			e.checkMembership(what+".coarse", v, refs)
			return
		}
		var exp []cell
		for i := range a.Parts {
			if i > 0 {
				exp = append(exp, refs[1].cells...)
			}
			exp = append(exp, refs[3+i].cells...)
		}
		e.checkBytes(what, v, exp)
	case 2:
		var exp []cell
		for i := 0; i < a.N; i++ {
			exp = append(exp, refs[0].cells...)
		}
		e.checkBytes(what, v, exp)
	default:
		e.checkMembership(what, v, refs)
	}
}

func (e *env) runFn() {
	a := e.randArgs()
	refs := e.inputs(a)
	e.trace = append(e.trace[:0], fnNames[a.Fn]+"/N"+strconv.Itoa(a.N)+"/parts"+strconv.Itoa(len(a.Parts)))
	wr := WovenFn(a)
	nr := NativeFn(a)
	we, ne := wr.enc(refs), nr.enc(refs)
	e.digest = append(e.digest, we...)
	e.stats["fn."+fnNames[a.Fn]]++
	if !bytes.Equal(we, ne) {
		e.fail("bytes.%s DIVERGES: args X=%q Y=%q Z=%q N=%d cut=%q parts=%q\n woven  %+v\n native %+v", fnNames[a.Fn], a.X, a.Y, a.Z, a.N, a.Cut, a.Parts, wr, nr)
		return
	}
	if wr.Panic != "" {
		e.stats["fn.panic."+fnNames[a.Fn]+"."+wr.Panic]++
		return
	}
	name := "fn." + fnNames[a.Fn]
	e.checkFnSlice(name+".A", a.Fn, wr.A, refs, a)
	e.checkFnSlice(name+".B", a.Fn, wr.B, refs, a)
	for _, v := range wr.List {
		e.checkFnSlice(name+".L", a.Fn, v, refs, a)
	}
	if a.Fn == 30 && e.active {
		e.checkString(name+".S", wr.S, refs[0].cells)
	}
}

func (e *env) runFns() {
	finish := e.newScope()
	defer finish()
	for i, n := 0, 1+e.rng.IntN(30); i < n; i++ {
		e.runFn()
	}
	if e.rng.IntN(16) == 0 {
		runtime.GC()
	}
}

func TestDiffBytesFnDeterministic(t *testing.T) {
	setupConfig(t)
	e := &env{t: t, rng: rand.New(rand.NewPCG(3, 4)), stats: map[string]int{}}
	n := iters(3000)
	for i := 0; i < n; i++ {
		e.active = i%4 != 0
		e.runFns()
	}
	report(t, "bytesfn", e, n)
}

func TestDiffBytesFnRandom(t *testing.T) {
	d := budget()
	if d == 0 {
		t.Skip("set DIFF_BUDGET")
	}
	setupConfig(t)
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed=%d", seed)
	e := &env{t: t, rng: rand.New(rand.NewPCG(seed, 9)), stats: map[string]int{}}
	deadline := time.Now().Add(d)
	n := 0
	for ; time.Now().Before(deadline) && e.fails == 0; n++ {
		e.active = n%4 != 0
		e.runFns()
	}
	report(t, "bytesfn-random", e, n)
}
