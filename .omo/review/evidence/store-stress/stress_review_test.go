// Randomized concurrent stress harness for the bounded taint store.
//
// Run with:
//
//	STORE_STRESS=1 STRESS_SEED=<n> STRESS_DURATION=30s GOMAXPROCS=16 \
//	  go test -race -run '^TestReviewStoreStress$' -count=1 ./internal/taint/store
//
// Environment:
//
//	STORE_STRESS=1         enable (skipped otherwise)
//	STRESS_SEED=<uint64>   op-choice seed (default: time based, always printed)
//	STRESS_DURATION=<dur>  wall-clock budget (default 10s)
//	STRESS_WORKERS=<n>     worker goroutines (default: 32..64 from seed)
//	STRESS_COLLIDE=0|1     force every key into one shard/slot (default: seed%4==0)
//
// Workers run epochs of random operations against one Store. Every op is
// followed by cheap bound checks and, where the worker owns the value, a strict
// model check of Lookup output. Between epochs all workers stop and the main
// goroutine checks full structural/accounting invariants on store internals.
package store

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

const (
	stressMaxOwnOwners  = 2
	stressMaxRoots      = 48
	stressMaxWriters    = 4
	stressMaxObjs       = 8
	stressSharedKeys    = 1024
	stressSharedOwners  = 128
	stressSharedWriters = 256
	stressBandWidth     = 1000
	stressBands         = 60
	stressMaxViolations = 50
)

type stressOwnerRec struct {
	h         *Owner
	id        uint64
	index     uint8
	gen       uint64
	band      uint16
	creator   int
	finishing atomic.Bool // set by the creator immediately before Finish
	finished  atomic.Bool // set after Finish returned
}

func (r *stressOwnerRec) source(rng *rand.Rand) ranges.SourceID {
	return ranges.SourceID(r.band*stressBandWidth + uint16(rng.IntN(stressBandWidth)))
}

type stressKey struct {
	key    Key
	lo, hi uint32
}

type stressRoot struct {
	rec      *stressOwnerRec
	ref      RootRef
	str      string
	buf      []byte
	isBytes  bool
	span     uint32
	full     []ranges.Range // canonical set published for the root
	keys     []stressKey
	adoption string
}

type stressAbsent struct {
	rec *stressOwnerRec
	key Key
	why string
}

type stressSharedKey struct {
	key    Key
	anchor any
	rec    *stressOwnerRec
}

type stressWriterObj struct {
	buf []byte
	tag [8]byte
}

type stressWriter struct {
	obj   *stressWriterObj
	rec   *stressOwnerRec
	kind  WriterKind
	ideal []int32
}

type stressSharedWriter struct {
	pointer, backing, capacity uintptr
}

type stressBindObj struct{ payload [16]byte }

type stressBind struct {
	obj       *stressBindObj
	owners    map[*stressOwnerRec]struct{}
	everBound []*stressOwnerRec
}

type stressHarness struct {
	t           *testing.T
	s           *Store
	seed        uint64
	epoch       atomic.Int64
	opMirror    atomic.Int32
	wMirror     atomic.Int32
	registry    sync.Map // owner ID -> *stressOwnerRec
	knownCounts sync.Map // class -> *atomic.Int64
	shared      [stressSharedKeys]atomic.Pointer[stressSharedKey]
	owners      [stressSharedOwners]atomic.Pointer[stressOwnerRec]
	writers     [stressSharedWriters]atomic.Pointer[stressSharedWriter]
	mu          sync.Mutex
	violations  []string
	nviol       atomic.Int64
	stats       struct {
		ops, acquireDisabled, strictHits, strictMisses, strictChecks           atomic.Int64
		mutations, mutationClaimFail, overflowSets, foreignDerive, staleFinish atomic.Int64
		writerSnapshots, bindLookups, quiescentChecks, leakedReservations      atomic.Int64
		fullWindows, maxFullWindows, wedgedCollide                             atomic.Int64
	}
}

type stressWorker struct {
	id       int
	h        *stressHarness
	rng      *rand.Rand
	own      []*stressOwnerRec
	stale    []*Owner
	roots    []*stressRoot
	absent   []stressAbsent
	writers  []*stressWriter
	objs     []*stressBind
	trace    [16]string
	traceN   int
	lastOp   string
	snapshot Snapshot
}

func (h *stressHarness) violate(w *stressWorker, format string, args ...any) {
	n := h.nviol.Add(1)
	if n > stressMaxViolations {
		return
	}
	msg := fmt.Sprintf(format, args...)
	who := "main"
	var trace string
	if w != nil {
		who = fmt.Sprintf("worker=%d op=%s", w.id, w.lastOp)
		var b strings.Builder
		for i := 0; i < len(w.trace); i++ {
			if s := w.trace[(w.traceN+i)%len(w.trace)]; s != "" {
				b.WriteString("\n      ")
				b.WriteString(s)
			}
		}
		trace = b.String()
	}
	full := fmt.Sprintf("VIOLATION seed=%d epoch=%d %s: %s%s", h.seed, h.epoch.Load(), who, msg, trace)
	fmt.Fprintln(os.Stderr, full)
	h.mu.Lock()
	h.violations = append(h.violations, full)
	h.mu.Unlock()
}

// known records a violation of an already-diagnosed class (see the review
// report). It is logged and counted but only fails the run with STRESS_STRICT=1,
// so the harness keeps exploring for new defects.
func (h *stressHarness) known(w *stressWorker, class string, format string, args ...any) {
	v, _ := h.knownCounts.LoadOrStore(class, new(atomic.Int64))
	if v.(*atomic.Int64).Add(1) <= 3 {
		fmt.Fprintf(os.Stderr, "KNOWN[%s] seed=%d epoch=%d worker=%d op=%s: %s\n", class, h.seed, h.epoch.Load(), w.id, w.lastOp, fmt.Sprintf(format, args...))
	}
	if os.Getenv("STRESS_STRICT") == "1" {
		h.violate(w, "["+class+"] "+format, args...)
	}
}

func (h *stressHarness) knownSummary() string {
	var b strings.Builder
	h.knownCounts.Range(func(k, v any) bool {
		fmt.Fprintf(&b, "%s=%d ", k, v.(*atomic.Int64).Load())
		return true
	})
	return b.String()
}

func (w *stressWorker) note(format string, args ...any) {
	w.lastOp = fmt.Sprintf(format, args...)
	w.trace[w.traceN%len(w.trace)] = w.lastOp
	w.traceN++
}

func stressEnv(t *testing.T) (seed uint64, dur time.Duration, workers int, collide bool) {
	seed = uint64(time.Now().UnixNano())
	if v := os.Getenv("STRESS_SEED"); v != "" {
		parsed, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			t.Fatalf("STRESS_SEED: %v", err)
		}
		seed = parsed
	}
	dur = 10 * time.Second
	if v := os.Getenv("STRESS_DURATION"); v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("STRESS_DURATION: %v", err)
		}
		dur = parsed
	}
	workers = 32 + int(seed%33)
	if v := os.Getenv("STRESS_WORKERS"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("STRESS_WORKERS: %v", err)
		}
		workers = parsed
	}
	collide = seed%4 == 0
	if v := os.Getenv("STRESS_COLLIDE"); v != "" {
		collide = v == "1"
	}
	return seed, dur, workers, collide
}

func TestReviewStoreStress(t *testing.T) {
	if os.Getenv("STORE_STRESS") != "1" {
		t.Skip("set STORE_STRESS=1 to run the randomized store stress harness")
	}
	seed, dur, nworkers, collide := stressEnv(t)
	fmt.Fprintf(os.Stderr, "STRESS seed=%d duration=%s workers=%d collide=%v\n", seed, dur, nworkers, collide)
	if collide {
		forceCollision.Store(true)
		defer forceCollision.Store(false)
	}
	h := &stressHarness{t: t, s: New(), seed: seed}
	h.s.BindOperatorActive(&h.opMirror)
	h.s.BindWriterActive(&h.wMirror)
	workers := make([]*stressWorker, nworkers)
	for i := range workers {
		workers[i] = &stressWorker{id: i, h: h, rng: rand.New(rand.NewPCG(seed, uint64(i)+1))}
	}
	mainRng := rand.New(rand.NewPCG(seed, 0))
	deadline := time.Now().Add(dur)
	for epoch := 0; time.Now().Before(deadline) && h.nviol.Load() == 0; epoch++ {
		h.epoch.Store(int64(epoch))
		ops := 100 + mainRng.IntN(1500)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, w := range workers {
			wg.Add(1)
			go func(w *stressWorker) {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						h.violate(w, "PANIC: %v\n%s", r, debug.Stack())
					}
				}()
				<-start
				for i := 0; i < ops && h.nviol.Load() == 0; i++ {
					w.step()
				}
			}(w)
		}
		close(start)
		wg.Wait()
		h.checkQuiescent(false)
	}
	// Drain: every creator finishes its owners, then the store must be empty.
	for _, w := range workers {
		for _, rec := range w.own {
			w.finishOwner(rec)
		}
		w.own = nil
	}
	h.checkQuiescent(true)
	t.Logf("seed=%d workers=%d collide=%v ops=%d epochs=%d acquireDisabled=%d strictChecks=%d strictHits=%d strictMisses=%d mutations=%d claimFail=%d overflowSets=%d foreignDerive=%d staleFinish=%d writerSnapshots=%d bindLookups=%d quiescent=%d leakedReservations=%d fullWindows=%d maxFullWindowsPerShard=%d collideWedgedTombstones=%d known={%s} stats=%+v",
		seed, nworkers, collide, h.stats.ops.Load(), h.epoch.Load()+1, h.stats.acquireDisabled.Load(), h.stats.strictChecks.Load(), h.stats.strictHits.Load(), h.stats.strictMisses.Load(),
		h.stats.mutations.Load(), h.stats.mutationClaimFail.Load(), h.stats.overflowSets.Load(), h.stats.foreignDerive.Load(), h.stats.staleFinish.Load(),
		h.stats.writerSnapshots.Load(), h.stats.bindLookups.Load(), h.stats.quiescentChecks.Load(), h.stats.leakedReservations.Load(),
		h.stats.fullWindows.Load(), h.stats.maxFullWindows.Load(), h.stats.wedgedCollide.Load(), h.knownSummary(), h.s.Stats())
	if n := h.nviol.Load(); n != 0 {
		h.mu.Lock()
		defer h.mu.Unlock()
		t.Fatalf("seed=%d: %d invariant violations; first:\n%s", seed, n, h.violations[0])
	}
}

// ---------------------------------------------------------------- ops

func (w *stressWorker) step() {
	h := w.h
	h.stats.ops.Add(1)
	w.checkOwnAlive()
	r := w.rng.IntN(1000)
	switch {
	case r < 40 || len(w.own) == 0 && r < 200:
		w.opAcquire()
	case r < 70:
		w.opFinish()
	case r < 90:
		w.opStaleFinish()
	case r < 300:
		w.opTaint()
	case r < 400:
		w.opDerive()
	case r < 560:
		w.opLookupOwn()
	case r < 640:
		w.opMutate()
	case r < 720:
		w.opForeign()
	case r < 740:
		w.opMayContain()
	case r < 880:
		w.opWriter()
	case r < 950:
		w.opBind()
	case r < 960:
		w.opStats()
	default:
		w.opCheckAbsent()
	}
	w.checkBounds()
}

func (w *stressWorker) checkOwnAlive() {
	for _, rec := range w.own {
		if !rec.finishing.Load() && !rec.h.alive() {
			w.h.known(w, "stale-finish-kills-reused-owner", "owner id=%d idx=%d gen=%d is no longer alive although its creator never finished it (slot gen=%d state=%d id=%d)",
				rec.id, rec.index, rec.gen, rec.h.owner.generation.Load(), rec.h.owner.state.Load(), rec.h.owner.id.Load())
			rec.finishing.Store(true) // report once
		}
	}
}

func (w *stressWorker) checkBounds() {
	s := w.h.s
	if v := s.values.Load(); v < 0 || v > ProcessValueLimit {
		w.h.violate(w, "process values out of bounds: %d", v)
	}
	if c := s.charged.Load(); c < 0 || c > ProcessRootBytes {
		w.h.violate(w, "process charged out of bounds: %d", c)
	}
	if ws := s.writerStates.Load(); ws < 0 || ws > MaxOwners*MaxWriters {
		w.h.violate(w, "writer states out of bounds: %d", ws)
	}
	for _, rec := range w.own {
		if rec.finishing.Load() {
			continue
		}
		o := rec.h.owner
		if v := o.values.Load(); v < 0 || v > RequestValueLimit {
			w.h.violate(w, "owner %d values out of bounds: %d", rec.id, v)
		}
		if c := o.charged.Load(); c < 0 || c > RequestRootBytes {
			w.h.violate(w, "owner %d charged out of bounds: %d", rec.id, c)
		}
		if rc := o.rootCount.Load(); rc < 0 || rc > MaxRootsPerOwner {
			w.h.violate(w, "owner %d rootCount out of bounds: %d", rec.id, rc)
		}
	}
}

func (w *stressWorker) opAcquire() {
	if len(w.own) >= stressMaxOwnOwners {
		return
	}
	w.note("acquire")
	o := w.h.s.Acquire()
	if o == nil {
		w.h.violate(w, "Acquire returned nil")
		return
	}
	if o.Disabled() {
		w.h.stats.acquireDisabled.Add(1)
		if o.ID() != 0 {
			w.h.violate(w, "disabled owner has non-zero ID")
		}
		return
	}
	idx, ok := o.Index()
	if !ok {
		w.h.violate(w, "enabled owner has no index")
		return
	}
	rec := &stressOwnerRec{h: o, id: o.ID(), index: idx, gen: o.Generation(), creator: w.id}
	rec.band = uint16(rec.id % stressBands)
	if rec.id == 0 || !o.alive() {
		w.h.violate(w, "fresh owner not alive or zero id: id=%d", rec.id)
	}
	if o.Values() != 0 || o.Charged() != 0 {
		w.h.violate(w, "fresh owner has residual counters values=%d charged=%d", o.Values(), o.Charged())
	}
	if _, dup := w.h.registry.LoadOrStore(rec.id, rec); dup {
		w.h.violate(w, "duplicate owner id %d", rec.id)
	}
	w.own = append(w.own, rec)
	w.h.owners[w.rng.IntN(stressSharedOwners)].Store(rec)
	w.note("acquire -> id=%d idx=%d gen=%d", rec.id, idx, rec.gen)
}

func (w *stressWorker) finishOwner(rec *stressOwnerRec) {
	rec.finishing.Store(true)
	rec.h.Finish()
	rec.finished.Store(true)
	if st := ownerState(rec.h.owner.state.Load()); rec.h.owner.generation.Load() == rec.gen && st != stateDead {
		w.h.violate(w, "owner %d state=%d after Finish returned", rec.id, st)
	}
	if rec.h.alive() {
		w.h.known(w, "torn-alive", "owner %d handle reports alive() after Finish returned (slot reused concurrently)", rec.id)
	}
	w.stale = append(w.stale, rec.h)
	if len(w.stale) > 8 {
		w.stale = w.stale[1:]
	}
}

func (w *stressWorker) opFinish() {
	if len(w.own) == 0 {
		return
	}
	i := w.rng.IntN(len(w.own))
	rec := w.own[i]
	w.note("finish id=%d", rec.id)
	w.finishOwner(rec)
	w.own = append(w.own[:i], w.own[i+1:]...)
	// Every value this worker holds for rec must now be absent from lookups.
	for _, root := range w.roots {
		if root.rec == rec {
			for _, k := range root.keys {
				w.absent = append(w.absent, stressAbsent{rec: rec, key: k.key, why: "owner finished"})
			}
		}
	}
	w.dropFinishedModels()
	w.opCheckAbsent()
}

func (w *stressWorker) opStaleFinish() {
	if len(w.stale) == 0 {
		return
	}
	w.h.stats.staleFinish.Add(1)
	old := w.stale[w.rng.IntN(len(w.stale))]
	w.note("stale finish idx=%d gen=%d", old.index, old.gen)
	old.Finish()
}

func (w *stressWorker) pickRec(foreignOK bool) *stressOwnerRec {
	if foreignOK && w.rng.IntN(4) == 0 {
		if rec := w.h.owners[w.rng.IntN(stressSharedOwners)].Load(); rec != nil {
			return rec
		}
	}
	if len(w.own) == 0 {
		return nil
	}
	return w.own[w.rng.IntN(len(w.own))]
}

func (w *stressWorker) randLen() int {
	switch r := w.rng.IntN(100); {
	case r < 4:
		return w.rng.IntN(2) // 0 or 1: must be rejected
	case r < 6:
		return MaxRootBytes + 1 + w.rng.IntN(16)
	case r < 10:
		return 1024 + w.rng.IntN(MaxRootBytes-1024+1)
	default:
		return 2 + w.rng.IntN(300)
	}
}

func (w *stressWorker) randBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + w.rng.IntN(26))
	}
	return b
}

// randSet builds a canonical range list over [0, length) with at most k ranges.
func (w *stressWorker) randSet(rec *stressOwnerRec, length uint32, k int) []ranges.Range {
	var out []ranges.Range
	pos := uint32(0)
	for len(out) < k && pos < length {
		gap := uint32(w.rng.IntN(4))
		start := pos + gap
		if start >= length {
			break
		}
		maxLen := length - start
		l := uint32(1 + w.rng.IntN(int(min(maxLen, 40))))
		src := rec.source(w.rng)
		if len(out) > 0 {
			prev := out[len(out)-1]
			if prev.Start+prev.Length == start && prev.SourceID == src {
				src = ranges.SourceID(rec.band*stressBandWidth + (uint16(src)-rec.band*stressBandWidth+1)%stressBandWidth)
			}
		}
		out = append(out, ranges.Range{Start: start, Length: l, SourceID: src})
		pos = start + l
	}
	return out
}

func mustSet(limit ranges.Limit, rs []ranges.Range, length uint32) (ranges.Set, bool) {
	var set ranges.Set
	return set, ranges.AdoptCanonical(&set, limit, rs, length).Valid
}

func (w *stressWorker) addRoot(root *stressRoot) {
	if len(w.roots) >= stressMaxRoots {
		i := w.rng.IntN(len(w.roots))
		w.roots = append(w.roots[:i], w.roots[i+1:]...)
	}
	w.roots = append(w.roots, root)
	k := root.keys[0]
	var anchor any = root.str
	if root.isBytes {
		anchor = root.buf
	}
	w.h.shared[w.rng.IntN(stressSharedKeys)].Store(&stressSharedKey{key: k.key, anchor: anchor, rec: root.rec})
	w.strictLookup(root, k, "post-publish")
}

func (w *stressWorker) opTaint() {
	rec := w.pickRec(true)
	if rec == nil {
		return
	}
	finishedBefore := rec.finished.Load()
	n := w.randLen()
	src := rec.source(w.rng)
	expectFail := n < 2 || n > MaxRootBytes
	kind := w.rng.IntN(7)
	w.note("taint kind=%d len=%d owner=%d", kind, n, rec.id)
	var root *stressRoot
	var ok bool
	switch kind {
	case 0, 1: // TaintString / TaintSourceString
		in := string(w.randBytes(n))
		var out string
		var ref RootRef
		if kind == 0 {
			out, ref, ok = rec.h.TaintString(in, src)
		} else {
			var name string
			out, name, ref, ok = rec.h.TaintSourceString(in, "hdr-"+strconv.Itoa(w.rng.IntN(100)), src)
			if ok && !strings.HasPrefix(name, "hdr-") {
				w.h.violate(w, "TaintSourceString corrupted name %q", name)
			}
		}
		if out != in {
			w.h.violate(w, "TaintString changed host value content (ok=%v)", ok)
		}
		if !ok && unsafe.StringData(out) != unsafe.StringData(in) {
			w.h.violate(w, "failed TaintString did not return the original value")
		}
		if ok {
			key, _ := StringKey(out)
			root = &stressRoot{rec: rec, ref: ref, str: out, span: uint32(n), full: []ranges.Range{{Length: uint32(n), SourceID: src}}, keys: []stressKey{{key: key, lo: 0, hi: uint32(n)}}, adoption: "TaintString"}
		}
	case 2, 3: // TaintBytes / TaintSourceBytes
		c := n + w.rng.IntN(64)
		in := make([]byte, n, c)
		copy(in, w.randBytes(n))
		var out []byte
		var ref RootRef
		if kind == 2 {
			out, ref, ok = rec.h.TaintBytes(in, src)
		} else {
			var mv string
			out, _, mv, ref, ok = rec.h.TaintSourceBytes(in, "form", src)
			if ok && mv != string(in) {
				w.h.violate(w, "TaintSourceBytes managedValue mismatch")
			}
		}
		if !bytes.Equal(out, in) || (ok && cap(out) != cap(in)) {
			w.h.violate(w, "TaintBytes changed host value/capacity (ok=%v)", ok)
		}
		if ok {
			if unsafe.SliceData(out) == unsafe.SliceData(in) {
				w.h.violate(w, "TaintBytes did not clone")
			}
			key, _ := BytesKey(out)
			root = &stressRoot{rec: rec, ref: ref, buf: out, isBytes: true, span: uint32(cap(out)), full: []ranges.Range{{Length: uint32(n), SourceID: src}}, keys: []stressKey{{key: key, lo: 0, hi: uint32(n)}}, adoption: "TaintBytes"}
		}
	case 4: // AdoptSourceBytes
		c := n + w.rng.IntN(64)
		in := make([]byte, n, c)
		copy(in, w.randBytes(n))
		var ref RootRef
		var mv string
		_, mv, ref, ok = rec.h.AdoptSourceBytes(in, "body", src)
		if ok {
			if mv != string(in) {
				w.h.violate(w, "AdoptSourceBytes managedValue mismatch")
			}
			key, _ := BytesKey(in)
			root = &stressRoot{rec: rec, ref: ref, buf: in, isBytes: true, span: uint32(cap(in)), full: []ranges.Range{{Length: uint32(n), SourceID: src}}, keys: []stressKey{{key: key, lo: 0, hi: uint32(n)}}, adoption: "AdoptSourceBytes"}
		}
	case 5: // AdoptString with a multi-range set (exercises overflow blocks)
		in := string(w.randBytes(n))
		rs := w.randSet(rec, uint32(max(n, 0)), 1+w.rng.IntN(24))
		set, valid := mustSet(ranges.HardLimit, rs, uint32(max(n, 0)))
		if len(rs) > GuaranteedRanges {
			w.h.stats.overflowSets.Add(1)
		}
		var ref RootRef
		ref, ok = rec.h.AdoptString(in, &set)
		if ok && !valid {
			w.h.violate(w, "AdoptString accepted invalid set")
		}
		if ok {
			key, _ := StringKey(in)
			root = &stressRoot{rec: rec, ref: ref, str: in, span: uint32(n), full: rs, keys: []stressKey{{key: key, lo: 0, hi: uint32(n)}}, adoption: "AdoptString"}
		}
	case 6: // AdoptBytes with a multi-range set over capacity
		c := n + w.rng.IntN(64)
		in := make([]byte, n, c)
		copy(in, w.randBytes(n))
		rs := w.randSet(rec, uint32(max(n, 0)), 1+w.rng.IntN(24))
		set, _ := mustSet(ranges.HardLimit, rs, uint32(c))
		if len(rs) > GuaranteedRanges {
			w.h.stats.overflowSets.Add(1)
		}
		var ref RootRef
		ref, ok = rec.h.AdoptBytes(in, &set)
		if ok {
			key, _ := BytesKey(in)
			root = &stressRoot{rec: rec, ref: ref, buf: in, isBytes: true, span: uint32(c), full: rs, keys: []stressKey{{key: key, lo: 0, hi: uint32(n)}}, adoption: "AdoptBytes"}
		}
	}
	if ok && expectFail {
		w.h.violate(w, "taint kind=%d accepted invalid length %d", kind, n)
	}
	if ok && finishedBefore {
		w.h.violate(w, "taint kind=%d succeeded on owner %d finished before the call", kind, rec.id)
	}
	if ok && root != nil {
		if len(root.full) == 0 {
			return
		}
		w.addRoot(root)
	}
}

func (w *stressWorker) pickRoot(bytesOnly bool) (int, *stressRoot) {
	if len(w.roots) == 0 {
		return -1, nil
	}
	for tries := 0; tries < 4; tries++ {
		i := w.rng.IntN(len(w.roots))
		r := w.roots[i]
		if r.rec.finished.Load() || (bytesOnly && !r.isBytes) {
			continue
		}
		return i, r
	}
	return -1, nil
}

func (w *stressWorker) opDerive() {
	_, root := w.pickRoot(false)
	if root == nil {
		return
	}
	visible := uint32(len(root.str))
	if root.isBytes {
		visible = root.keys[0].hi // current visible length
	}
	if visible < 3 {
		return
	}
	// Own derived windows always have even length >= 2 (foreign ones are odd).
	l := uint32(2 + 2*w.rng.IntN(int((visible-1)/2)))
	if l > visible {
		return
	}
	lo := uint32(w.rng.IntN(int(visible - l + 1)))
	var key Key
	if root.isBytes {
		key, _ = BytesKey(root.buf[lo : lo+l])
	} else {
		key, _ = StringKey(root.str[lo : lo+l])
	}
	w.note("derive owner=%d root=%v [%d,%d)", root.rec.id, root.ref, lo, lo+l)
	finishedBefore := root.rec.finished.Load()
	if !root.rec.h.Derive(key, root.ref) {
		return
	}
	if finishedBefore {
		w.h.violate(w, "Derive succeeded on owner %d finished before the call", root.rec.id)
	}
	for _, k := range root.keys {
		if k.key == key {
			w.strictLookup(root, k, "re-derive")
			return
		}
	}
	k := stressKey{key: key, lo: lo, hi: lo + l}
	root.keys = append(root.keys, k)
	w.removeAbsent(root.rec, key)
	w.strictLookup(root, k, "post-derive")
}

func (w *stressWorker) removeAbsent(rec *stressOwnerRec, key Key) {
	out := w.absent[:0]
	for _, a := range w.absent {
		if !(a.rec == rec && a.key == key) {
			out = append(out, a)
		}
	}
	w.absent = out
}

func (w *stressWorker) opLookupOwn() {
	_, root := w.pickRoot(false)
	if root == nil {
		return
	}
	k := root.keys[w.rng.IntN(len(root.keys))]
	w.note("lookup owner=%d root=%v [%d,%d)", root.rec.id, root.ref, k.lo, k.hi)
	w.strictLookup(root, k, "lookup")
}

// expand converts a canonical range list to a per-byte source map for [lo,hi).
func expand(rs []ranges.Range, lo, hi uint32) []int32 {
	out := make([]int32, hi-lo)
	for _, r := range rs {
		for b := max(r.Start, lo); b < min(r.Start+r.Length, hi); b++ {
			out[b-lo] = int32(r.SourceID) + 1
		}
	}
	return out
}

func setMap(set *ranges.Set, length uint32) ([]int32, bool) {
	out := make([]int32, length)
	for i := 0; i < set.Len(); i++ {
		r, _ := set.At(i)
		if r.Start+r.Length > length || r.Length == 0 {
			return out, false
		}
		for b := r.Start; b < r.Start+r.Length; b++ {
			out[b] = int32(r.SourceID) + 1
		}
	}
	return out, true
}

func equalMap(a, b []int32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (h *stressHarness) laxEntry(w *stressWorker, e *Entry, key Key, finishedBefore func(uint64) bool) *stressOwnerRec {
	v, ok := h.registry.Load(e.OwnerID)
	if !ok {
		h.violate(w, "lookup entry for unknown owner id=%d idx=%d gen=%d", e.OwnerID, e.OwnerIndex, e.OwnerGen)
		return nil
	}
	rec := v.(*stressOwnerRec)
	if rec.index != e.OwnerIndex || rec.gen != e.OwnerGen {
		h.violate(w, "lookup entry id=%d has idx/gen %d/%d but owner was %d/%d", e.OwnerID, e.OwnerIndex, e.OwnerGen, rec.index, rec.gen)
	}
	if finishedBefore(e.OwnerID) {
		h.violate(w, "lookup returned entry for owner id=%d that finished before the lookup started", e.OwnerID)
	}
	if !e.Ranges.ValidFor(key.Length) {
		h.violate(w, "lookup entry ranges invalid for length %d", key.Length)
	}
	for i := 0; i < e.Ranges.Len(); i++ {
		r, _ := e.Ranges.At(i)
		if uint16(r.SourceID)/stressBandWidth != rec.band {
			h.violate(w, "cross-owner source: entry owner=%d band=%d contains source %d (band %d)", rec.id, rec.band, r.SourceID, uint16(r.SourceID)/stressBandWidth)
		}
	}
	return rec
}

func (w *stressWorker) strictLookup(root *stressRoot, k stressKey, why string) {
	h := w.h
	h.stats.strictChecks.Add(1)
	finishedBefore := root.rec.finished.Load()
	if !h.s.Lookup(k.key, &w.snapshot) {
		return
	}
	var found *Entry
	for i := 0; i < w.snapshot.Len(); i++ {
		e, _ := w.snapshot.At(i)
		rec := h.laxEntry(w, e, k.key, func(id uint64) bool { return id == root.rec.id && finishedBefore })
		if rec == nil {
			continue
		}
		if rec != root.rec {
			h.violate(w, "%s: private key [%d,%d) of owner %d resolved to foreign owner %d", why, k.lo, k.hi, root.rec.id, rec.id)
			continue
		}
		if found != nil {
			h.violate(w, "%s: duplicate entries for owner %d", why, rec.id)
		}
		found = e
	}
	if found == nil {
		if !finishedBefore {
			h.stats.strictMisses.Add(1)
		}
		return
	}
	h.stats.strictHits.Add(1)
	if found.Root != root.ref {
		h.violate(w, "%s: entry root %v, model root %v (%s)", why, found.Root, root.ref, root.adoption)
	}
	got, ok := setMap(&found.Ranges, k.key.Length)
	if !ok {
		h.violate(w, "%s: entry ranges out of window", why)
		return
	}
	want := expand(root.full, k.lo, k.hi)
	if equalMap(got, want) {
		return
	}
	if len(root.full) > GuaranteedRanges && equalMap(got, expand(root.full[:GuaranteedRanges], k.lo, k.hi)) {
		return // overflow block unavailable: documented truncation to the guaranteed prefix
	}
	h.violate(w, "%s: wrong provenance for owner %d root %v [%d,%d) (%s): got %v want %v", why, root.rec.id, root.ref, k.lo, k.hi, root.adoption, compactMap(got), compactMap(want))
}

func compactMap(m []int32) string {
	var b strings.Builder
	for i := 0; i < len(m); {
		j := i
		for j < len(m) && m[j] == m[i] {
			j++
		}
		if m[i] != 0 {
			fmt.Fprintf(&b, "[%d,%d)=%d ", i, j, m[i]-1)
		}
		i = j
	}
	return b.String()
}

func (w *stressWorker) opCheckAbsent() {
	h := w.h
	keep := w.absent[:0]
	for _, a := range w.absent {
		w.note("check-absent owner=%d why=%s", a.rec.id, a.why)
		if h.s.Lookup(a.key, &w.snapshot) {
			for i := 0; i < w.snapshot.Len(); i++ {
				e, _ := w.snapshot.At(i)
				if e.OwnerID == a.rec.id {
					h.violate(w, "stale provenance: key for owner %d still resolves after %s (root %v ranges=%d)", a.rec.id, a.why, e.Root, e.Ranges.Len())
				}
			}
		}
		if w.rng.IntN(4) != 0 {
			keep = append(keep, a)
		}
	}
	w.absent = keep
	if len(w.absent) > 256 {
		w.absent = w.absent[len(w.absent)-256:]
	}
}

func (w *stressWorker) dropFinishedModels() {
	roots := w.roots[:0]
	for _, r := range w.roots {
		if !r.rec.finished.Load() {
			roots = append(roots, r)
		}
	}
	w.roots = roots
	writers := w.writers[:0]
	for _, wr := range w.writers {
		if !wr.rec.finished.Load() {
			writers = append(writers, wr)
		}
	}
	w.writers = writers
	objs := w.objs[:0]
	for _, o := range w.objs {
		for rec := range o.owners {
			if rec.finished.Load() {
				delete(o.owners, rec)
			}
		}
		objs = append(objs, o)
	}
	w.objs = objs
}

func (w *stressWorker) opMutate() {
	i, root := w.pickRoot(true)
	if root == nil {
		return
	}
	h := w.h
	h.stats.mutations.Add(1)
	c := int(root.span)
	n := 1 + w.rng.IntN(c)
	value := root.buf[:n:c]
	for j := 0; j < min(n, 4); j++ {
		value[w.rng.IntN(n)] ^= 0x20
	}
	k := 0
	switch w.rng.IntN(4) {
	case 0:
		k = 0
	case 1:
		k = 11 + w.rng.IntN(20)
	default:
		k = 1 + w.rng.IntN(10)
	}
	rs := w.randSet(root.rec, uint32(n), k)
	set, _ := mustSet(ranges.HardLimit, rs, uint32(c))
	if len(rs) > GuaranteedRanges {
		h.stats.overflowSets.Add(1)
	}
	w.note("mutate owner=%d root=%v len=%d ranges=%d", root.rec.id, root.ref, n, len(rs))
	finishedBefore := root.rec.finished.Load()
	old := root.ref
	next, ok := root.rec.h.PublishBytesMutation(old, value, &set)
	key, _ := BytesKey(value)
	if ok {
		if finishedBefore {
			h.violate(w, "mutation succeeded on owner %d finished before the call", root.rec.id)
		}
		if next.ID != old.ID || next.Generation == old.Generation {
			h.violate(w, "mutation returned bad ref %v from %v", next, old)
		}
		for _, k := range root.keys {
			if k.key != key {
				w.absent = append(w.absent, stressAbsent{rec: root.rec, key: k.key, why: fmt.Sprintf("mutation %v->%v", old, next)})
			}
		}
		root.ref = next
		root.buf = value
		root.full = rs
		root.keys = []stressKey{{key: key, lo: 0, hi: uint32(n)}}
		w.removeAbsent(root.rec, key)
		if len(rs) == 0 {
			// Empty provenance: the key must resolve to nothing for this owner.
			w.absent = append(w.absent, stressAbsent{rec: root.rec, key: key, why: "mutation to empty set"})
			w.roots = append(w.roots[:i], w.roots[i+1:]...)
		} else {
			w.strictLookup(root, root.keys[0], "post-mutation")
		}
		w.opCheckAbsent()
		return
	}
	// Failure: decide whether the generation was claimed (old provenance must be gone).
	if root.rec.h.owner.roots[old.ID].generation.Load() != old.Generation || root.rec.finished.Load() {
		h.stats.mutationClaimFail.Add(1)
		for _, k := range root.keys {
			w.absent = append(w.absent, stressAbsent{rec: root.rec, key: k.key, why: fmt.Sprintf("failed mutation claimed %v", old)})
		}
		w.roots = append(w.roots[:i], w.roots[i+1:]...)
		w.opCheckAbsent()
	}
}

func (w *stressWorker) opForeign() {
	h := w.h
	sk := h.shared[w.rng.IntN(stressSharedKeys)].Load()
	if sk == nil {
		return
	}
	w.note("foreign lookup owner=%d", sk.rec.id)
	finished := sk.rec.finished.Load()
	if !h.s.Lookup(sk.key, &w.snapshot) {
		return
	}
	var snap Snapshot = w.snapshot
	for i := 0; i < snap.Len(); i++ {
		e, _ := snap.At(i)
		h.laxEntry(w, e, sk.key, func(id uint64) bool { return id == sk.rec.id && finished })
	}
	if snap.Len() == 0 || sk.key.Length < 5 || w.rng.IntN(2) == 0 {
		return
	}
	// Foreign derive through Entry.Handle: odd length, never at the base.
	e, _ := snap.At(0)
	handle, ok := e.Handle(h.s)
	if !ok {
		return
	}
	l := uint32(3 + 2*w.rng.IntN(int((sk.key.Length-3)/2)))
	if l >= sk.key.Length {
		return
	}
	lo := uint32(1 + w.rng.IntN(int(sk.key.Length-l)))
	var key Key
	switch a := sk.anchor.(type) {
	case string:
		key, _ = StringKey(a[lo : lo+l])
	case []byte:
		key, _ = BytesKey(a[lo : lo+l])
	}
	v, _ := h.registry.Load(e.OwnerID)
	rec, _ := v.(*stressOwnerRec)
	finishedBefore := rec != nil && rec.finished.Load()
	w.note("foreign derive owner=%d root=%v [%d,%d)", e.OwnerID, e.Root, lo, lo+l)
	if handle.Derive(key, e.Root) {
		h.stats.foreignDerive.Add(1)
		if finishedBefore {
			h.violate(w, "foreign Derive succeeded on owner %d finished before the call", e.OwnerID)
		}
	}
}

func (w *stressWorker) opMayContain() {
	sk := w.h.shared[w.rng.IntN(stressSharedKeys)].Load()
	if sk == nil {
		return
	}
	w.note("maycontain")
	w.h.s.MayContain(sk.key)
	w.h.s.MayContain(Key{Pointer: uintptr(w.rng.Uint64()) | 1, Length: uint32(1 + w.rng.IntN(64)), Kind: KindString})
}

func (w *stressWorker) opStats() {
	w.note("stats")
	st := w.h.s.Stats()
	if st.MaxProbe > ProbeLimit || st.OverflowFree > OverflowBlocks || st.MaxTombstones > SlotsPerShard {
		w.h.violate(w, "stats out of bounds: %+v", st)
	}
}

// ---------------------------------------------------------------- writers

func stressView(wr *stressWriter) WriterView {
	buf := wr.obj.buf
	if cap(buf) == 0 {
		return WriterView{}
	}
	p := uintptr(unsafe.Pointer(unsafe.SliceData(buf)))
	v := WriterView{Pointer: p, Length: uint32(len(buf)), Capacity: uint32(cap(buf))}
	if wr.kind == WriterBytesBuffer {
		v.Backing = p
		v.Anchor = unsafe.SliceData(buf)
	}
	return v
}

func (w *stressWorker) publishWriter(wr *stressWriter) {
	v := stressView(wr)
	w.h.writers[w.rng.IntN(stressSharedWriters)].Store(&stressSharedWriter{
		pointer: uintptr(unsafe.Pointer(wr.obj)), backing: v.Backing, capacity: uintptr(v.Capacity),
	})
}

func (w *stressWorker) opWriter() {
	h := w.h
	r := w.rng.IntN(100)
	if r < 10 {
		// Foreign invalidation of another worker's receiver or backing.
		sw := h.writers[w.rng.IntN(stressSharedWriters)].Load()
		if sw == nil {
			return
		}
		w.note("writer invalidate foreign")
		if w.rng.IntN(2) == 0 {
			h.s.InvalidateWriterPointer(sw.pointer)
		} else {
			h.s.InvalidateBuffer(sw.pointer, sw.backing, sw.capacity, w.rng.IntN(2) == 0)
		}
		return
	}
	if len(w.writers) == 0 || (len(w.writers) < stressMaxWriters && r < 20) {
		rec := w.pickRec(true)
		if rec == nil || rec.finished.Load() {
			return
		}
		kind := WriterStringBuilder
		if w.rng.IntN(2) == 0 {
			kind = WriterBytesBuffer
		}
		wr := &stressWriter{obj: &stressWriterObj{}, rec: rec, kind: kind}
		w.writers = append(w.writers, wr)
		w.publishWriter(wr)
		return
	}
	wi := w.rng.IntN(len(w.writers))
	wr := w.writers[wi]
	if wr.rec.finished.Load() {
		w.writers = append(w.writers[:wi], w.writers[wi+1:]...)
		return
	}
	o := wr.rec.h
	switch op := w.rng.IntN(10); {
	case op < 5: // write
		n := 1 + w.rng.IntN(64)
		before := stressView(wr)
		buf := wr.obj.buf
		if len(buf)+n > cap(buf) {
			newCap := max(2*cap(buf), len(buf)+n, 16)
			if newCap > MaxRootBytes {
				w.note("writer reset (full)")
				o.ResetWriter(wr.obj, wr.kind)
				wr.obj.buf, wr.ideal = nil, nil
				return
			}
			grown := make([]byte, len(buf), newCap)
			copy(grown, buf)
			buf = grown
		}
		buf = append(buf, w.randBytes(n)...)
		wr.obj.buf = buf
		after := stressView(wr)
		rs := w.randSet(wr.rec, uint32(n), w.rng.IntN(3))
		var input *ranges.Set
		if len(rs) > 0 {
			set, _ := mustSet(ranges.DefaultLimit, rs, uint32(n))
			input = &set
		}
		w.note("writer update owner=%d kind=%d n=%d ranges=%d", wr.rec.id, wr.kind, n, len(rs))
		o.UpdateWriter(wr.obj, wr.kind, before, after, input, uint32(n), uint32(n))
		wr.ideal = append(wr.ideal, expand(rs, 0, uint32(n))...)
		if before.Pointer != after.Pointer {
			w.publishWriter(wr)
		}
	case op < 7: // snapshot
		w.snapshotWriter(wr)
	case op < 8: // truncate
		if len(wr.obj.buf) == 0 {
			return
		}
		before := stressView(wr)
		nl := w.rng.IntN(len(wr.obj.buf) + 1)
		wr.obj.buf = wr.obj.buf[:nl]
		wr.ideal = wr.ideal[:nl]
		w.note("writer truncate owner=%d to %d", wr.rec.id, nl)
		o.TruncateWriter(wr.obj, wr.kind, before, stressView(wr))
	case op < 9: // reset
		w.note("writer reset owner=%d", wr.rec.id)
		o.ResetWriter(wr.obj, wr.kind)
		wr.obj.buf = wr.obj.buf[:0]
		wr.ideal = wr.ideal[:0]
	default: // discovery
		var out [MaxSnapshotOwners]WriterRef
		w.note("writer lookup owner=%d", wr.rec.id)
		n := LookupWriterValue(h.s, wr.obj, wr.kind, stressView(wr), out[:])
		for i := 0; i < n; i++ {
			if out[i].index == wr.rec.index && out[i].generation > wr.rec.gen {
				h.known(w, "stale-handle-writer", "LookupWriterValue returned reused slot idx=%d gen=%d for writer of owner gen=%d", out[i].index, out[i].generation, wr.rec.gen)
			} else if out[i].index != wr.rec.index || out[i].generation != wr.rec.gen {
				h.violate(w, "LookupWriterValue returned foreign owner idx=%d gen=%d for writer of owner idx=%d gen=%d", out[i].index, out[i].generation, wr.rec.index, wr.rec.gen)
			}
		}
	}
}

func (w *stressWorker) snapshotWriter(wr *stressWriter) {
	view := stressView(wr)
	var dst ranges.Set
	w.note("writer snapshot owner=%d len=%d", wr.rec.id, view.Length)
	if !wr.rec.h.SnapshotWriter(wr.obj, wr.kind, view, &dst) {
		return
	}
	w.h.stats.writerSnapshots.Add(1)
	if !dst.ValidFor(view.Length) {
		w.h.violate(w, "writer snapshot invalid for length %d", view.Length)
		return
	}
	got, _ := setMap(&dst, view.Length)
	for b := range got {
		if got[b] != 0 && (b >= len(wr.ideal) || got[b] != wr.ideal[b]) {
			w.h.violate(w, "writer snapshot invents/misplaces provenance at byte %d: got %v ideal %v", b, compactMap(got), compactMap(wr.ideal))
			return
		}
	}
}

// ---------------------------------------------------------------- bindings

func (w *stressWorker) opBind() {
	h := w.h
	if len(w.objs) == 0 || (len(w.objs) < stressMaxObjs && w.rng.IntN(4) == 0) {
		w.objs = append(w.objs, &stressBind{obj: &stressBindObj{}, owners: map[*stressOwnerRec]struct{}{}})
	}
	b := w.objs[w.rng.IntN(len(w.objs))]
	if w.rng.IntN(2) == 0 {
		rec := w.pickRec(true)
		if rec == nil {
			return
		}
		kind := BindingURL
		if w.rng.IntN(2) == 0 {
			kind = BindingReader
		}
		w.note("bind owner=%d kind=%d", rec.id, kind)
		finishedBefore := rec.finished.Load()
		b.everBound = append(b.everBound, rec)
		if len(b.everBound) > 64 {
			b.everBound = b.everBound[1:]
		}
		var ok bool
		if w.rng.IntN(2) == 0 {
			ok = BindObject(rec.h, b.obj, kind)
		} else {
			ok = BindObjectValue(rec.h, b.obj, kind)
		}
		if ok {
			if finishedBefore {
				h.known(w, "stale-handle-bind", "BindObject succeeded on owner %d finished before the call", rec.id)
			} else {
				b.owners[rec] = struct{}{}
			}
		}
		return
	}
	h.stats.bindLookups.Add(1)
	var out [MaxSnapshotOwners]OwnerRef
	w.note("lookup object")
	n := LookupObject(h.s, b.obj, out[:])
	for i := 0; i < n; i++ {
		found := false
		for rec := range b.owners {
			if rec.index == out[i].index && rec.gen == out[i].generation {
				found = true
			}
		}
		if !found {
			stale := false
			for _, v := range b.everBound {
				if v.index == out[i].index && v.gen < out[i].generation {
					stale = true
				}
			}
			if stale {
				h.known(w, "stale-handle-bind", "LookupObject returned reused slot idx=%d gen=%d; object was bound only by an older generation", out[i].index, out[i].generation)
			} else {
				h.violate(w, "LookupObject returned owner idx=%d gen=%d that never bound this object", out[i].index, out[i].generation)
			}
		}
	}
}

// ---------------------------------------------------------------- quiescent invariants

func (h *stressHarness) checkQuiescent(final bool) {
	h.stats.quiescentChecks.Add(1)
	s := h.s
	fail := func(format string, args ...any) { h.violate(nil, "quiescent: "+format, args...) }

	var sumValues, liveSlots [MaxOwners]int32
	var rootRefs [MaxOwners][MaxRootsPerOwner]int32
	type dupKey struct {
		key Key
		idx uint8
		gen uint64
	}
	seen := map[dupKey]bool{}
	for si := range s.shards {
		sh := &s.shards[si]
		tomb := 0
		for i := range sh.slots {
			slot := &sh.slots[i]
			if slot.pointer == tombstone {
				tomb++
				continue
			}
			if slot.pointer == 0 {
				continue
			}
			// Reachability: from its initial slot without crossing an empty slot.
			hash := keyHash(Key{Pointer: slot.pointer, Length: slot.length, Kind: slot.kind})
			if int(shardIndex(hash)) != si {
				fail("slot in wrong shard %d", si)
			}
			start := int(initialSlot(hash))
			dist := (i - start + SlotsPerShard) % SlotsPerShard
			reachable := dist < ProbeLimit
			for d := 0; reachable && d < dist; d++ {
				if sh.slots[(start+d)%SlotsPerShard].pointer == 0 {
					reachable = false
				}
			}
			live := false
			if slot.ownerIdx < MaxOwners && slot.rootID < MaxRootsPerOwner {
				o := &s.owners[slot.ownerIdx]
				root := &o.roots[slot.rootID]
				live = o.generation.Load() == slot.ownerGen && ownerState(o.state.Load()) == stateActive &&
					root.generation.Load() == slot.rootGen && root.setGen == slot.rootGen && slot.rootGen != 0
				if live {
					if uint64(slot.rootOff)+uint64(slot.length) > uint64(root.span) {
						fail("live slot window [%d,+%d) exceeds root span %d", slot.rootOff, slot.length, root.span)
					}
					if slot.pointer != root.base+uintptr(slot.rootOff) {
						fail("live slot pointer does not match root base+offset")
					}
					liveSlots[slot.ownerIdx]++
					rootRefs[slot.ownerIdx][slot.rootID]++
					dk := dupKey{Key{slot.pointer, slot.length, slot.kind}, slot.ownerIdx, slot.ownerGen}
					if seen[dk] {
						fail("duplicate live slot for owner idx=%d key=%+v", slot.ownerIdx, dk.key)
					}
					seen[dk] = true
				}
			}
			if live && !reachable {
				fail("live slot in shard %d at %d unreachable from initial slot %d", si, i, start)
			}
		}
		if int(sh.tombstones) != tomb {
			fail("shard %d tombstone counter %d != actual %d", si, sh.tombstones, tomb)
		}
		// A probe window with no empty slot can never accept an insert; once its
		// occupants are stale, only a compaction triggered by a *successful*
		// insert elsewhere in the shard can reopen it.
		full := 0
		empty := 0
		for start := 0; start < SlotsPerShard; start++ {
			hasEmpty := false
			for d := 0; d < ProbeLimit && !hasEmpty; d++ {
				hasEmpty = sh.slots[(start+d)%SlotsPerShard].pointer == 0
			}
			if !hasEmpty {
				full++
			}
			if sh.slots[start].pointer == 0 {
				empty++
			}
		}
		if full > 0 {
			h.stats.fullWindows.Add(int64(full))
			if int64(full) > h.stats.maxFullWindows.Load() {
				h.stats.maxFullWindows.Store(int64(full))
			}
		}
		if final && !forceCollision.Load() && empty == 0 {
			fail("shard %d has no empty slot after every owner finished: permanently wedged (tombstones=%d)", si, sh.tombstones)
		}
		if final && forceCollision.Load() && si == 0 && full > 0 && sh.slots[0].pointer != 0 {
			h.stats.wedgedCollide.Store(int64(sh.tombstones))
		}
	}

	var totalValues, totalCharged int64
	var totalWriters int32
	inUse := map[uint16]string{}
	for oi := range s.owners {
		o := &s.owners[oi]
		st := ownerState(o.state.Load())
		if st == stateFinishing {
			fail("owner %d left in finishing state", oi)
		}
		if st != stateActive {
			if o.values.Load() != 0 || o.charged.Load() != 0 || o.rootCount.Load() != 0 || o.writerCount != 0 || o.bindings.count != 0 {
				fail("inactive owner %d has residue values=%d charged=%d roots=%d writers=%d bindings=%d",
					oi, o.values.Load(), o.charged.Load(), o.rootCount.Load(), o.writerCount, o.bindings.count)
			}
			for ri := range o.roots {
				if o.roots[ri].generation.Load() != 0 || o.roots[ri].stringAnchor != "" || o.roots[ri].bytesAnchor != nil || o.roots[ri].overflow != 0 {
					fail("inactive owner %d root %d not cleared", oi, ri)
					break
				}
			}
			continue
		}
		if final {
			fail("owner %d still active after drain", oi)
		}
		totalValues += int64(o.values.Load())
		totalCharged += o.charged.Load()
		totalWriters += int32(o.writerCount)
		sumValues[oi] = o.values.Load()
		if sumValues[oi] != liveSlots[oi] {
			fail("owner %d values counter %d != live index slots %d", oi, sumValues[oi], liveSlots[oi])
		}
		published := int32(0)
		for ri := range o.roots {
			root := &o.roots[ri]
			gen := root.generation.Load()
			if gen == 0 {
				if rootRefs[oi][ri] != 0 {
					fail("owner %d root %d unpublished but referenced", oi, ri)
				}
				continue
			}
			published++
			q := root.valueQuota.Load()
			qc := int32(uint32(q))
			if uint32(q>>32) != gen {
				qc = 0
			}
			if qc != rootRefs[oi][ri] {
				fail("owner %d root %d gen %d quota count %d != live refs %d", oi, ri, gen, qc, rootRefs[oi][ri])
			}
			if qc > MaxValuesPerRoot {
				fail("owner %d root %d quota %d > MaxValuesPerRoot", oi, ri, qc)
			}
			if root.count > GuaranteedRanges && root.overflow == 0 {
				fail("owner %d root %d count %d without overflow block", oi, ri, root.count)
			}
			if root.overflow != 0 {
				if prev, dup := inUse[root.overflow]; dup {
					fail("overflow block %d shared by %s and owner %d root %d", root.overflow-1, prev, oi, ri)
				}
				inUse[root.overflow] = fmt.Sprintf("owner %d root %d", oi, ri)
			}
		}
		// rollbackRoot may lose its TryLock and deliberately keep a reserved but
		// unpublished slot (and its charge) until Finish; count, don't fail.
		if published > o.rootCount.Load() {
			fail("owner %d rootCount %d < published roots %d", oi, o.rootCount.Load(), published)
		} else if leaked := o.rootCount.Load() - published; leaked > 0 {
			h.stats.leakedReservations.Add(int64(leaked))
		}
		freeSeen := map[uint16]bool{}
		for i := 0; i < int(o.rootFreeN); i++ {
			id := o.rootFree[i]
			if freeSeen[id] || id >= o.rootNext || o.roots[id].generation.Load() != 0 {
				fail("owner %d root free list corrupt at %d (id=%d)", oi, i, id)
			}
			freeSeen[id] = true
		}
		if int32(o.rootNext)-int32(o.rootFreeN) != o.rootCount.Load() {
			fail("owner %d rootNext %d - free %d != rootCount %d", oi, o.rootNext, o.rootFreeN, o.rootCount.Load())
		}
		var writerCharged int64
		for wi := 0; wi < MaxWriters; wi++ {
			if wi < int(o.writerCount) {
				writerCharged += o.writers[wi].charged
				if o.writerPointers[wi].Load() != o.writers[wi].pointer {
					fail("owner %d writer %d index pointer stale", oi, wi)
				}
			} else if o.writerPointers[wi].Load() != 0 || o.writers[wi].object != nil {
				fail("owner %d writer %d beyond count not cleared", oi, wi)
			}
		}
		if o.writerVersion.Load()&1 != 0 {
			fail("owner %d writer version odd at rest", oi)
		}
		if writerCharged > o.charged.Load() {
			fail("owner %d writer charge %d exceeds owner charge %d", oi, writerCharged, o.charged.Load())
		}
		readers := 0
		for i := 0; i < int(o.bindings.count); i++ {
			if o.bindings.entries[i].kind == BindingReader {
				readers++
			}
			if o.bindings.entries[i].object == nil {
				fail("owner %d binding %d has nil anchor", oi, i)
			}
		}
		if readers != int(o.bindings.readerCount) || readers > MaxReaderBindings {
			fail("owner %d reader count %d != actual %d", oi, o.bindings.readerCount, readers)
		}
	}
	if int64(s.values.Load()) != totalValues {
		fail("process values %d != sum of owner values %d", s.values.Load(), totalValues)
	}
	if h.opMirror.Load() != s.values.Load() {
		fail("operator mirror %d != process values %d", h.opMirror.Load(), s.values.Load())
	}
	if s.charged.Load() != totalCharged {
		fail("process charged %d != sum of owner charged %d", s.charged.Load(), totalCharged)
	}
	if s.writerStates.Load() != totalWriters || h.wMirror.Load() != totalWriters {
		fail("writer states %d / mirror %d != sum of writer counts %d", s.writerStates.Load(), h.wMirror.Load(), totalWriters)
	}
	freeSeen := map[uint16]bool{}
	for i := 0; i < int(s.overflowN); i++ {
		b := s.overflowFree[i] + 1
		if freeSeen[b] {
			fail("overflow block %d twice in free list", b-1)
		}
		freeSeen[b] = true
		if who, used := inUse[b]; used {
			fail("overflow block %d free but used by %s", b-1, who)
		}
	}
	if int(s.overflowN)+len(inUse) != OverflowBlocks {
		fail("overflow accounting: free %d + in use %d != %d", s.overflowN, len(inUse), OverflowBlocks)
	}
	if final {
		if s.values.Load() != 0 || s.charged.Load() != 0 || s.writerStates.Load() != 0 || s.overflowN != OverflowBlocks || h.opMirror.Load() != 0 || h.wMirror.Load() != 0 {
			fail("store not empty after drain: values=%d charged=%d writers=%d overflowFree=%d opMirror=%d wMirror=%d",
				s.values.Load(), s.charged.Load(), s.writerStates.Load(), s.overflowN, h.opMirror.Load(), h.wMirror.Load())
		}
	}
}
