package zzdiffbytes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

// cell is the expected provenance of one byte: -1 clean, otherwise the index
// of the source value in the scope's source table.
type cell = int16

const unknownCell cell = -3

type env struct {
	t             *testing.T
	rng           *rand.Rand
	ctx           context.Context
	active        bool
	sources       []string // source values by index
	strs          []string // tainted string pool
	byts          [][]byte // tainted byte pool
	digest        []byte   // accumulated woven-side descriptors
	stats         map[string]int
	fails         int
	trace         []string
	supportedOnly bool
	lostLog       int
}

func (e *env) fail(format string, args ...any) {
	e.fails++
	if e.fails <= 40 {
		e.t.Errorf(format+"\n  trace: %v", append(args, e.trace)...)
	}
}

var alphabet = []string{"a", "b", ",", " ", "\n", "x", "é", "İ", "ß", "\xff", "\xe2\x82", "Σ", "ﬀ", "\t", "0", "'"}

func (e *env) randText(max int) string {
	n := e.rng.IntN(max + 1)
	var out []byte
	for i := 0; i < n; i++ {
		out = append(out, alphabet[e.rng.IntN(len(alphabet))]...)
	}
	return string(out)
}

func (e *env) sourceIndex(v string) int16 {
	for i, s := range e.sources {
		if s == v {
			return int16(i)
		}
	}
	return -2
}

// cellsOfString derives the expected per-byte provenance of an input from the
// ranges the system itself reports on that input.
func (e *env) cellsOfString(v string) []cell {
	cells := make([]cell, len(v))
	for i := range cells {
		cells[i] = -1
	}
	if !e.active {
		return cells
	}
	taint.VisitString(v, func(r taint.Range) bool {
		idx := e.sourceIndex(r.Source.Value)
		for i := r.Start; i < r.Start+r.Length && int(i) < len(cells); i++ {
			cells[i] = idx
		}
		return true
	})
	return cells
}

func (e *env) cellsOfBytes(v []byte) []cell {
	cells := make([]cell, len(v))
	for i := range cells {
		cells[i] = -1
	}
	if !e.active {
		return cells
	}
	taint.VisitBytes(v, func(r taint.Range) bool {
		idx := e.sourceIndex(r.Source.Value)
		for i := r.Start; i < r.Start+r.Length && int(i) < len(cells); i++ {
			cells[i] = idx
		}
		return true
	})
	return cells
}

func tainted(cells []cell) int {
	n := 0
	for _, c := range cells {
		if c >= 0 {
			n++
		}
	}
	return n
}

// checkRanges asserts that every reported range covers only bytes the model
// says are tainted, with the model's source. It returns the number of reported
// tainted bytes.
func (e *env) checkRanges(what string, visit func(func(taint.Range) bool) bool, n int, cells []cell) int {
	if !e.active {
		return 0
	}
	seen := 0
	visit(func(r taint.Range) bool {
		for i := r.Start; i < r.Start+r.Length; i++ {
			seen++
			if int(i) >= n {
				e.fail("%s: range [%d,+%d) exceeds length %d", what, r.Start, r.Length, n)
				return false
			}
			if int(i) < len(cells) && cells[i] == unknownCell {
				continue
			}
			if int(i) >= len(cells) || cells[i] < 0 {
				e.fail("%s: FALSE TAINT at byte %d (range [%d,+%d) source %q), model=%v", what, i, r.Start, r.Length, r.Source.Value, cells)
				return false
			}
			if e.sources[cells[i]] != r.Source.Value {
				e.fail("%s: WRONG SOURCE at byte %d: got %q want %q", what, i, r.Source.Value, e.sources[cells[i]])
				return false
			}
		}
		return true
	})
	exp := tainted(cells)
	runs := 0
	for i, c := range cells {
		if c >= 0 && (i == 0 || cells[i-1] != c) {
			runs++
		}
	}
	if runs > 10 {
		what += ".over-range-limit"
	}
	if exp > 0 {
		e.stats[what+".expected"]++
		if seen == 0 {
			e.stats[what+".lost"]++
			if e.supportedOnly && n >= 2 {
				e.stats[what+".lost.len>=2"]++
				e.lostLog++
				if e.lostLog <= 12 {
					e.t.Logf("LOST %s len=%d model=%v trace=%v", what, n, cells, e.trace)
				}
			}
		} else if seen < exp {
			e.stats[what+".partial"]++
		}
	}
	return seen
}

func (e *env) checkString(what, v string, cells []cell) {
	e.checkRanges(what, func(f func(taint.Range) bool) bool { return taint.VisitString(v, f) }, len(v), cells)
}

func (e *env) checkBytes(what string, v []byte, cells []cell) {
	e.checkRanges(what, func(f func(taint.Range) bool) bool { return taint.VisitBytes(v, f) }, len(v), cells)
}

// newScope begins a request analysis and fills the tainted pools.
func (e *env) newScope() func() {
	e.sources, e.strs, e.byts = nil, nil, nil
	if !e.active {
		e.ctx = context.Background()
		return func() {}
	}
	ctx, scope, created := request.Begin(context.Background())
	if !created {
		e.t.Fatalf("request.Begin did not create a scope")
	}
	e.ctx = ctx
	n := 1 + e.rng.IntN(3)
	for i := 0; i < n; i++ {
		v := e.randText(12)
		if len(v) < 2 {
			v += "qq"
		}
		// Make source values unique so the model maps values to indices.
		v += strconv.Itoa(i) + strconv.Itoa(e.rng.IntN(1000))
		src := taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "p" + strconv.Itoa(i)}
		if e.rng.IntN(2) == 0 {
			ts := taint.TaintString(ctx, src, v)
			e.sources = append(e.sources, v)
			e.strs = append(e.strs, ts)
			if !taint.IsTaintedString(ts) {
				e.stats["source.string.untainted"]++
			}
		} else {
			tb := taint.TaintBytes(ctx, src, []byte(v))
			e.sources = append(e.sources, v)
			e.byts = append(e.byts, tb)
			if !taint.IsTaintedBytes(tb) {
				e.stats["source.bytes.untainted"]++
			}
		}
	}
	return scope.Finish
}

func (e *env) pickString() string {
	switch k := e.rng.IntN(6); {
	case k < 2 || (len(e.strs) == 0 && len(e.byts) == 0):
		return e.randText(8)
	case k < 4 && len(e.strs) > 0:
		return e.strs[e.rng.IntN(len(e.strs))]
	case len(e.strs) > 0:
		s := e.strs[e.rng.IntN(len(e.strs))]
		a := e.rng.IntN(len(s) + 1)
		b := a + e.rng.IntN(len(s)-a+1)
		return s[a:b]
	default:
		b := e.byts[e.rng.IntN(len(e.byts))]
		return string(b) // alloc-preserving conversion propagates
	}
}

func (e *env) pickBytes() []byte {
	switch k := e.rng.IntN(7); {
	case k < 2 || len(e.byts) == 0:
		if k == 0 {
			return nil
		}
		return []byte(e.randText(8))
	case k < 4:
		return e.byts[e.rng.IntN(len(e.byts))]
	case k < 6:
		b := e.byts[e.rng.IntN(len(e.byts))]
		lo := e.rng.IntN(len(b) + 1)
		hi := lo + e.rng.IntN(len(b)-lo+1)
		if e.rng.IntN(2) == 0 {
			return b[lo:hi:hi]
		}
		return b[lo:hi]
	default:
		return []byte(e.pickString())
	}
}

func (e *env) randOp(builder bool) Op {
	op := Op{Ptr: e.rng.IntN(2) == 0}
	if e.supportedOnly {
		kinds := []int{OpWrite, OpWriteString, OpWriteString, OpWriteByte, OpWriteRune, OpGrow, OpString, OpString}
		if e.rng.IntN(10) == 0 {
			kinds = []int{OpReset, OpTruncate}
			if builder {
				kinds = []int{OpReset}
			}
		}
		op.Kind = kinds[e.rng.IntN(len(kinds))]
	} else if builder {
		kinds := []int{OpWrite, OpWriteString, OpWriteString, OpWriteByte, OpWriteRune, OpGrow, OpReset, OpString, OpString, OpSelfWriteString, OpLenCap, OpCopyWrite, OpNilRecv}
		op.Kind = kinds[e.rng.IntN(len(kinds))]
	} else {
		op.Kind = e.rng.IntN(OpCount)
		if e.rng.IntN(3) == 0 {
			op.Kind = []int{OpWrite, OpWriteString, OpString}[e.rng.IntN(3)]
		}
	}
	switch op.Kind {
	case OpWrite:
		op.Bs = e.pickBytes()
	case OpWriteString, OpReadFrom, OpAvailAppendWrite, OpCopyWrite:
		op.S = e.pickString()
	case OpNilRecv:
		op.S, op.Bs = e.pickString(), e.pickBytes()
	}
	op.N = e.rng.IntN(24) - 2
	if e.rng.IntN(40) == 0 {
		op.N = -5
	}
	if op.Kind == OpGrow && e.rng.IntN(10) == 0 && os.Getenv("DIFF_NO_BIG_GROW") == "" {
		op.N = 70000
	}
	op.C = ",\n a\xff"[e.rng.IntN(5)]
	op.R = []rune{'a', 'é', 0x10FFFF, -1, 0xD800, 'Σ', '\n'}[e.rng.IntN(7)]
	if op.N < 0 && (op.Kind == OpRead || op.Kind == OpNext || op.Kind == OpPeek || op.Kind == OpPeekMutate) {
		if op.Kind == OpRead {
			op.N = 0
		}
	}
	return op
}

func clean(n int) []cell {
	c := make([]cell, n)
	for i := range c {
		c[i] = -1
	}
	return c
}

func opName(op Op) string {
	return fmt.Sprintf("k%d/p%v/n%d/len%d", op.Kind, op.Ptr, op.N, len(op.S)+len(op.Bs))
}

func internalOff(b *bytes.Buffer) int { return (*bufInternal)(unsafe.Pointer(b)).off }

func (e *env) runBufferSeq(nops int) {
	h, nh := &BufHolder{}, &BufHolder{}
	if e.rng.IntN(5) == 0 {
		init := e.pickString()
		h.B = *bytes.NewBufferString(init)
		nh.B = *bytes.NewBufferString(init)
	}
	// full mirrors the provenance of the native twin's internal buf[:len].
	full := clean(len(BufBase(&nh.B)))
	e.trace = e.trace[:0]
	for i := 0; i < nops; i++ {
		op := e.randOp(false)
		var inCells []cell
		if op.Kind == OpWrite {
			inCells = e.cellsOfBytes(op.Bs)
		} else if op.Kind == OpWriteString || op.Kind == OpCopyWrite || op.Kind == OpNilRecv {
			inCells = e.cellsOfString(op.S)
		}
		e.trace = append(e.trace, opName(op))
		off := internalOff(&nh.B)
		before := append([]cell(nil), full[off:]...)
		wr := WovenBuffer(h, op)
		nr := NativeBuffer(nh, op)
		we := BufState(wr.Enc(nil), &h.B)
		ne := BufState(nr.Enc(nil), &nh.B)
		e.digest = append(e.digest, we...)
		if !bytes.Equal(we, ne) {
			e.fail("buffer op %s DIVERGES:\n woven  %+v\n native %+v\n wstate %q\n nstate %q", opName(op), wr, nr, BufState(nil, &h.B), BufState(nil, &nh.B))
			return
		}
		noff, nlen := internalOff(&nh.B), len(BufBase(&nh.B))
		if nr.Panic != "" {
			e.stats["buffer.panic."+nr.Panic]++
		}
		appendWrite := func(added []cell) {
			var prefix []cell
			if noff == off {
				prefix = full[:off]
			} else {
				prefix = clean(noff)
			}
			full = append(append(append([]cell(nil), prefix...), before...), added...)
		}
		if nr.Panic == "" {
			switch op.Kind {
			case OpWrite, OpWriteString:
				appendWrite(inCells[:nr.N])
			case OpWriteByte:
				appendWrite(clean(1))
			case OpWriteRune, OpAvailAppendWrite:
				appendWrite(clean(nr.N))
			case OpReadFrom:
				appendWrite(clean(int(nr.N64)))
			case OpGrow:
				appendWrite(nil)
			case OpSelfWriteBytes, OpSelfWriteString:
				appendWrite(before)
			case OpTruncate:
				full = full[:off+op.N]
			case OpReset:
				full = nil
			case OpString:
				e.checkString("buffer.String", wr.S, before)
			case OpRead:
				e.checkBytes("buffer.Read.dst", wr.Bs[:wr.N], before[:wr.N])
			case OpReadBytes:
				e.checkBytes("buffer.ReadBytes", wr.Bs, before[:len(wr.Bs)])
			case OpReadString:
				e.checkString("buffer.ReadString", wr.S, before[:len(wr.S)])
			case OpBytes:
				e.checkBytes("buffer.Bytes", wr.Bs, before)
			case OpNext:
				e.checkBytes("buffer.Next", wr.Bs, before[:len(wr.Bs)])
			case OpPeek:
				e.checkBytes("buffer.Peek", wr.Bs, before[:len(wr.Bs)])
			case OpBytesMutate:
				if len(before) > 0 {
					full[off+op.N%len(before)] = -1
				}
			case OpPeekMutate:
				for k := 0; k < op.N && off+k < len(full); k++ {
					full[off+k] = -1
				}
			case OpCopyWrite:
				e.checkString("buffer.copy.String", wr.S, append(append([]cell(nil), before...), inCells[:nr.N]...))
			}
		}
		if nlen == 0 {
			full = nil
		}
		if len(full) != nlen {
			e.t.Fatalf("model length %d != internal length %d (off %d->%d) after %s (harness bug)", len(full), nlen, off, noff, opName(op))
		}
	}
	final := WovenBuffer(h, Op{Kind: OpString, Ptr: true})
	e.checkString("buffer.final.String", final.S, full[internalOff(&nh.B):])
	runtime.KeepAlive(nh)
}

func (e *env) runBuilderSeq(nops int) {
	h, nh := &BldHolder{}, &BldHolder{}
	var model []cell
	e.trace = e.trace[:0]
	for i := 0; i < nops; i++ {
		op := e.randOp(true)
		var inCells []cell
		if op.Kind == OpWrite {
			inCells = e.cellsOfBytes(op.Bs)
		} else if op.Kind == OpWriteString || op.Kind == OpCopyWrite {
			inCells = e.cellsOfString(op.S)
		}
		e.trace = append(e.trace, opName(op))
		before := append([]cell(nil), model...)
		wr := WovenBuilder(h, op)
		nr := NativeBuilder(nh, op)
		we := BldState(wr.Enc(nil), &h.B)
		ne := BldState(nr.Enc(nil), &nh.B)
		e.digest = append(e.digest, we...)
		if !bytes.Equal(we, ne) {
			e.fail("builder op %s DIVERGES:\n woven  %+v\n native %+v", opName(op), wr, nr)
			return
		}
		if nr.Panic != "" {
			e.stats["builder.panic."+nr.Panic]++
			continue
		}
		switch op.Kind {
		case OpWrite, OpWriteString:
			model = append(model, inCells[:nr.N]...)
		case OpWriteByte:
			model = append(model, -1)
		case OpWriteRune:
			model = append(model, clean(nr.N)...)
		case OpReset:
			model = nil
		case OpString:
			e.checkString("builder.String", wr.S, before)
		case OpSelfWriteString:
			model = append(model, before...)
		case OpCopyWrite:
			e.checkString("builder.copy.String", wr.S, append(before, inCells[:nr.N]...))
		}
	}
	final := WovenBuilder(h, Op{Kind: OpString, Ptr: true})
	e.checkString("builder.final.String", final.S, model)
}

func setupConfig(t *testing.T) {
	pe, ps, pm := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() { config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = pe, ps, pm })
}

func iters(def int) int {
	if v, err := strconv.Atoi(os.Getenv("DIFF_ITERS")); err == nil {
		return v
	}
	return def
}

func budget() time.Duration {
	if v, err := time.ParseDuration(os.Getenv("DIFF_BUDGET")); err == nil {
		return v
	}
	return 0
}

// runWriters runs one scope worth of sequences.
func (e *env) runWriters() {
	finish := e.newScope()
	defer finish()
	for s, n := 0, 1+e.rng.IntN(3); s < n; s++ {
		if e.rng.IntN(2) == 0 {
			e.runBufferSeq(1 + e.rng.IntN(40))
		} else {
			e.runBuilderSeq(1 + e.rng.IntN(40))
		}
		if e.rng.IntN(8) == 0 {
			runtime.GC()
		}
	}
}

func report(t *testing.T, name string, e *env, n int) {
	sum := sha256.Sum256(e.digest)
	t.Logf("%s: woven=%v iterations=%d DIGEST=%s", name, built.WithOrchestrion, n, hex.EncodeToString(sum[:8]))
	keys := make([]string, 0, len(e.stats))
	for k := range e.stats {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		t.Logf("  stat %-60s %d", k, e.stats[k])
	}
}

func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

// TestDiffWritersDeterministic uses a fixed seed; its digest must be identical
// between plain and woven builds.
func TestDiffWritersDeterministic(t *testing.T) {
	setupConfig(t)
	e := &env{t: t, rng: rand.New(rand.NewPCG(1, 2)), stats: map[string]int{}}
	n := iters(3000)
	for i := 0; i < n; i++ {
		e.active = i%4 != 0
		e.runWriters()
	}
	report(t, "writers", e, n)
}

func TestDiffWritersRandom(t *testing.T) {
	d := budget()
	if d == 0 {
		t.Skip("set DIFF_BUDGET")
	}
	setupConfig(t)
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed=%d", seed)
	e := &env{t: t, rng: rand.New(rand.NewPCG(seed, 7)), stats: map[string]int{}}
	deadline := time.Now().Add(d)
	n := 0
	for ; time.Now().Before(deadline) && e.fails == 0; n++ {
		e.active = n%4 != 0
		e.runWriters()
	}
	report(t, "writers-random", e, n)
}

// TestDiffWritersSupportedOnly restricts sequences to README-supported direct
// writer operations and reports provenance loss rates.
func TestDiffWritersSupportedOnly(t *testing.T) {
	setupConfig(t)
	e := &env{t: t, rng: rand.New(rand.NewPCG(5, 6)), stats: map[string]int{}, supportedOnly: true}
	n := iters(3000)
	for i := 0; i < n; i++ {
		e.active = true
		e.runWriters()
	}
	report(t, "writers-supported", e, n)
}
