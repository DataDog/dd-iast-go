// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

// Model-based sequence fuzzer (review node store-fuzz). Every operation's
// outcome is predicted from a simple reference model BEFORE the real call; the
// real result, the returned values, every accounting counter, the physical
// index invariants and the visible lookups must all match the model.

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

const (
	fzHandles  = 6
	fzMaxOps   = 256
	fzMaxBytes = 96 << 20 // harness-retained bytes per iteration
)

type fzIn struct {
	data []byte
	pos  int
}

func (f *fzIn) more() bool { return f.pos < len(f.data) }
func (f *fzIn) b() byte {
	if f.pos >= len(f.data) {
		return 0
	}
	v := f.data[f.pos]
	f.pos++
	return v
}
func (f *fzIn) n(m int) int {
	if m <= 0 {
		return 0
	}
	return (int(f.b()) | int(f.b())<<8) % m
}

var fzLengths = [...]int{0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 100, 255, 256, 1000, 1024, 1025, 4096, 8192, 32768, 32769, 65535, 65536, 65537}

func (f *fzIn) length() int {
	v := f.b()
	if v < 160 {
		return int(v) % 48
	}
	return fzLengths[int(v)%len(fzLengths)]
}

type mRoot struct {
	owner     *mOwner
	id        uint16
	gen       uint32 // internal root generation
	callerGen uint32 // last generation handed to the caller
	valid     bool   // setGen == gen
	kind      Kind
	base      uintptr
	span      uint32
	charge    int64
	rs        []ranges.Range
	limit     ranges.Limit
	overflow  bool
	windows   map[Key]struct{}
	str       string
	buf       []byte
}

type mWindow struct {
	root *mRoot
	off  uint32
}

type mWriter struct {
	ptr    uintptr
	view   WriterView
	set    ranges.Set
	charge int64
}

type mOwner struct {
	h        *Owner
	alive    bool
	idx      uint8
	gen      uint64
	id       uint64
	roots    map[uint16]*mRoot
	list     []*mRoot
	values   int
	bindings map[uintptr]BindingKind
	bindN    int
	readers  int
	writers  []*mWriter
	entries  []Entry
}

func (o *mOwner) charged() int64 {
	var c int64
	for _, r := range o.roots {
		c += r.charge
	}
	for _, w := range o.writers {
		c += w.charge
	}
	return c
}

type wKey struct {
	o *mOwner
	k Key
}

type fzObj struct{ v [2]int }

type harness struct {
	t         testing.TB
	s         *Store
	opActive  atomic.Int32
	wrActive  atomic.Int32
	slots     [fzHandles]*mOwner
	dead      []*mOwner
	busy      [MaxOwners]bool
	slotGen   [MaxOwners]uint64
	lastID    uint64
	windows   map[wKey]*mWindow
	keys      []Key
	seen      map[Key]bool
	allRoots  []*mRoot
	objs      []*fzObj
	builders  [4]*strings.Builder
	held      int // overflow blocks held by model roots
	keep      []any
	kept      int
	trace     []string
	sample    int
	probeSkip int
	crowded   int
}

func newHarness(t testing.TB) *harness {
	h := &harness{t: t, s: New(), windows: map[wKey]*mWindow{}, seen: map[Key]bool{}}
	h.s.BindOperatorActive(&h.opActive)
	h.s.BindWriterActive(&h.wrActive)
	for i := 0; i < 12; i++ {
		h.objs = append(h.objs, &fzObj{})
	}
	for i := range h.builders {
		h.builders[i] = new(strings.Builder)
	}
	return h
}

func (h *harness) logf(format string, args ...any) {
	h.trace = append(h.trace, fmt.Sprintf(format, args...))
}

func (h *harness) fatalf(format string, args ...any) {
	h.t.Helper()
	tail := h.trace
	if len(tail) > 40 {
		tail = tail[len(tail)-40:]
	}
	h.t.Fatalf("%s\ntrace (last %d ops):\n  %s", fmt.Sprintf(format, args...), len(tail), strings.Join(tail, "\n  "))
}

func (h *harness) retain(v any, n int) {
	h.keep = append(h.keep, v)
	h.kept += n
}

func (h *harness) addKey(k Key) {
	if !h.seen[k] {
		h.seen[k] = true
		h.keys = append(h.keys, k)
	}
}

func (h *harness) processCharged() int64 {
	var c int64
	for _, o := range h.aliveOwners() {
		c += o.charged()
	}
	return c
}

func (h *harness) processValues() int {
	n := 0
	for _, o := range h.aliveOwners() {
		n += o.values
	}
	return n
}

func (h *harness) aliveOwners() []*mOwner {
	var out []*mOwner
	for _, o := range h.slots {
		if o != nil && o.alive {
			out = append(out, o)
		}
	}
	return out
}

func (h *harness) owner(f *fzIn) *mOwner {
	slot := f.n(fzHandles)
	if h.slots[slot] == nil {
		h.acquire(slot)
	}
	return h.slots[slot]
}

// ---- random range sets ----

func fzSet(f *fzIn, span uint32) (ranges.Set, []ranges.Range) {
	var set ranges.Set
	limit := ranges.Limit(1 + f.n(64))
	if f.b()%3 == 0 {
		limit = ranges.Limit(config.MaxRangeCount)
	}
	want := f.n(ranges.HardLimit + 1)
	raw := make([]ranges.Range, 0, want)
	pos := uint32(0)
	for i := 0; i < want; i++ {
		gap := uint32(f.n(4))
		length := uint32(1 + f.n(8))
		if uint64(pos)+uint64(gap)+uint64(length) > uint64(span) {
			break
		}
		r := ranges.Range{Start: pos + gap, Length: length, SourceID: ranges.SourceID(f.n(4)), Marks: uint64(f.b()&0x6) &^ 1}
		if n := len(raw); n > 0 && gap == 0 && raw[n-1].SourceID == r.SourceID && raw[n-1].Marks == r.Marks {
			r.SourceID++
		}
		raw = append(raw, r)
		pos = r.Start + r.Length
	}
	if !ranges.AdoptCanonical(&set, limit, raw, span).Valid {
		panic("fzSet generated a non-canonical set")
	}
	stored := make([]ranges.Range, set.Len())
	set.CopyTo(stored)
	return set, stored
}

func sliceRanges(rs []ranges.Range, low, high uint32) []ranges.Range {
	var out []ranges.Range
	for _, r := range rs {
		s, e := max(r.Start, low), min(r.Start+r.Length, high)
		if s < e {
			out = append(out, ranges.Range{Start: s - low, Length: e - s, SourceID: r.SourceID, Marks: r.Marks})
		}
	}
	return out
}

func setSlice(s *ranges.Set) []ranges.Range {
	out := make([]ranges.Range, s.Len())
	s.CopyTo(out)
	return out
}

func equalRanges(a, b []ranges.Range) bool {
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

// ---- index predicates ----

func (h *harness) probeHasEmpty(k Key) bool {
	hash := keyHash(k)
	sh := &h.s.shards[shardIndex(hash)]
	start := initialSlot(hash)
	for p := 0; p < ProbeLimit; p++ {
		if sh.slots[(start+uint8(p))%SlotsPerShard].pointer == 0 {
			return true
		}
	}
	return false
}

func (h *harness) anyProbeWindowFull() bool {
	for i := range h.s.shards {
		sh := &h.s.shards[i]
		for start := 0; start < SlotsPerShard; start++ {
			full := true
			for p := 0; p < ProbeLimit; p++ {
				if sh.slots[(start+p)%SlotsPerShard].pointer == 0 {
					full = false
					break
				}
			}
			if full {
				return true
			}
		}
	}
	return false
}

// predictPut mirrors putWindow's admission for a live owner and valid root.
// needProbe reports that success additionally requires a free probe slot.
func (h *harness) predictPut(o *mOwner, k Key, r *mRoot, quota int) (ok, needProbe bool) {
	if w := h.windows[wKey{o, k}]; w != nil {
		if w.root == r {
			return true, false
		}
		return quota < MaxValuesPerRoot, false
	}
	if o.values >= RequestValueLimit || h.processValues() >= ProcessValueLimit || quota < 0 || quota >= MaxValuesPerRoot {
		return false, false
	}
	return true, true
}

func (h *harness) applyPut(o *mOwner, k Key, r *mRoot, off uint32) {
	wk := wKey{o, k}
	if w := h.windows[wk]; w != nil {
		if w.root != r {
			delete(w.root.windows, k)
			r.windows[k] = struct{}{}
			w.root, w.off = r, off
		}
		return
	}
	h.windows[wk] = &mWindow{root: r, off: off}
	r.windows[k] = struct{}{}
	o.values++
	h.addKey(k)
}

func (h *harness) dropRootWindows(r *mRoot) {
	for k := range r.windows {
		delete(h.windows, wKey{r.owner, k})
		r.owner.values--
	}
	r.windows = map[Key]struct{}{}
}

// ---- lifecycle ----

func (h *harness) acquire(slot int) {
	if o := h.slots[slot]; o != nil && o.alive {
		return
	}
	want := -1
	for i := range h.busy {
		if !h.busy[i] {
			want = i
			break
		}
	}
	handle := h.s.Acquire()
	h.logf("acquire slot=%d -> disabled=%v", slot, handle.Disabled())
	if want < 0 {
		if !handle.Disabled() {
			h.fatalf("acquire succeeded with all owner slots busy")
		}
		return
	}
	if handle.Disabled() {
		h.fatalf("acquire disabled with free owner slot %d", want)
	}
	idx, ok := handle.Index()
	if !ok || int(idx) != want {
		h.fatalf("acquire index=%d ok=%v, want lowest free %d", idx, ok, want)
	}
	h.slotGen[want]++
	if handle.Generation() != h.slotGen[want] {
		h.fatalf("acquire generation=%d want %d", handle.Generation(), h.slotGen[want])
	}
	h.lastID++
	if handle.ID() != h.lastID {
		h.fatalf("acquire id=%d want %d", handle.ID(), h.lastID)
	}
	if handle.Charged() != 0 || handle.Values() != 0 || handle.Counters() != (Counters{}) {
		h.fatalf("fresh owner carries state: charged=%d values=%d counters=%+v", handle.Charged(), handle.Values(), handle.Counters())
	}
	h.busy[want] = true
	h.slots[slot] = &mOwner{h: handle, alive: true, idx: idx, gen: handle.Generation(), id: handle.ID(), roots: map[uint16]*mRoot{}, bindings: map[uintptr]BindingKind{}}
}

func (h *harness) finish(o *mOwner) {
	h.logf("finish owner idx=%d gen=%d alive=%v", o.idx, o.gen, o.alive)
	o.h.Finish()
	if !o.alive {
		return
	}
	for _, r := range o.roots {
		if r.overflow {
			h.held--
		}
		h.dropRootWindows(r)
	}
	o.roots = map[uint16]*mRoot{}
	o.list = nil
	o.writers = nil
	o.bindings = map[uintptr]BindingKind{}
	o.bindN, o.readers = 0, 0
	o.alive = false
	h.busy[o.idx] = false
	h.dead = append(h.dead, o)
	if o.h.Charged() != 0 || o.h.Values() != 0 {
		h.fatalf("finished owner retains charged=%d values=%d", o.h.Charged(), o.h.Values())
	}
	for i := range o.entries {
		if _, ok := o.entries[i].Handle(h.s); ok {
			h.fatalf("entry handle survived owner finish")
		}
	}
}

// ---- root creation ----

type newRootPlan struct {
	ok        bool // predicted success
	probeOnly bool // failure additionally acceptable only for an unknowable probe bound
	stored    []ranges.Range
	overflow  bool
}

func (h *harness) planRoot(o *mOwner, charge int64, key Key, keyKnown bool, rs []ranges.Range) newRootPlan {
	if !o.alive {
		return newRootPlan{}
	}
	if charge <= 0 || charge > MaxRootChargeBytes || len(o.roots) >= MaxRootsPerOwner || o.charged()+charge > RequestRootBytes || h.processCharged()+charge > ProcessRootBytes {
		return newRootPlan{}
	}
	plan := newRootPlan{stored: rs}
	if len(rs) > GuaranteedRanges {
		if OverflowBlocks-h.held > 0 {
			plan.overflow = true
		} else {
			plan.stored = rs[:GuaranteedRanges]
		}
	}
	probe := &mRoot{}
	var ok, needProbe bool
	if keyKnown {
		ok, needProbe = h.predictPut(o, key, probe, 0)
	} else {
		ok, needProbe = h.predictPut(o, Key{Pointer: 1, Length: 1, Kind: KindString}, probe, 0)
	}
	if !ok {
		return newRootPlan{}
	}
	if needProbe {
		if keyKnown {
			if !h.probeHasEmpty(key) {
				return newRootPlan{}
			}
		} else {
			plan.probeOnly = true
		}
	}
	plan.ok = true
	return plan
}

func (h *harness) commitRoot(o *mOwner, plan newRootPlan, ref RootRef, key Key, kind Kind, span uint32, charge int64, limit ranges.Limit, str string, buf []byte) {
	if ref.ID >= MaxRootsPerOwner || o.roots[ref.ID] != nil {
		h.fatalf("new root id %d invalid or already live", ref.ID)
	}
	if ref.Generation != 1 {
		h.fatalf("new root generation=%d want 1", ref.Generation)
	}
	r := &mRoot{owner: o, id: ref.ID, gen: ref.Generation, callerGen: ref.Generation, valid: true, kind: kind, base: key.Pointer, span: span, charge: charge, rs: plan.stored, limit: limit, overflow: plan.overflow, windows: map[Key]struct{}{}, str: str, buf: buf}
	o.roots[ref.ID] = r
	o.list = append(o.list, r)
	h.allRoots = append(h.allRoots, r)
	if plan.overflow {
		h.held++
	}
	h.applyPut(o, key, r, 0)
}

func (h *harness) checkOutcome(name string, plan newRootPlan, ok bool, o *mOwner) bool {
	if ok == plan.ok {
		return ok
	}
	if !ok && plan.probeOnly {
		if !h.anyProbeWindowFull() {
			h.fatalf("%s failed; model predicted success and no probe window is full", name)
		}
		h.probeSkip++
		return false
	}
	h.fatalf("%s ok=%v, model predicted %v (owner alive=%v roots=%d charged=%d values=%d procCharged=%d procValues=%d)", name, ok, plan.ok, o.alive, len(o.roots), o.charged(), o.values, h.processCharged(), h.processValues())
	return false
}

func fzString(f *fzIn, n int) string {
	var sb strings.Builder
	sb.Grow(n)
	c := byte('a' + f.b()%26)
	for i := 0; i < n; i++ {
		sb.WriteByte(c + byte(i%7))
	}
	return sb.String()
}

func (h *harness) opTaintString(o *mOwner, f *fzIn, source bool) {
	n := f.length()
	value := fzString(f, n)
	name := ""
	if source {
		name = fzString(f, f.length())
	}
	h.retain(value, n)
	h.retain(name, len(name))
	if k, ok := StringKey(value); ok {
		h.addKey(k) // an input value must never become tainted
	}
	src := ranges.SourceID(f.n(8))
	charge := sizeClass(n)
	if source {
		charge += sizeClass(len(name))
	}
	plan := newRootPlan{}
	if n >= 2 && n <= MaxRootBytes && len(name) <= MaxRootBytes {
		plan = h.planRoot(o, charge, Key{}, false, []ranges.Range{{Length: uint32(n), SourceID: src}})
	}
	var managed, managedName string
	var ref RootRef
	var ok bool
	if source {
		managed, managedName, ref, ok = o.h.TaintSourceString(value, name, src)
	} else {
		managed, ref, ok = o.h.TaintString(value, src)
	}
	h.logf("taintString source=%v len=%d nameLen=%d -> ok=%v ref=%+v", source, n, len(name), ok, ref)
	if managed != value {
		h.fatalf("TaintString changed content")
	}
	if !h.checkOutcome("TaintString", plan, ok, o) {
		if n > 0 && unsafe.StringData(managed) != unsafe.StringData(value) {
			h.fatalf("failed TaintString returned a different backing")
		}
		return
	}
	if unsafe.StringData(managed) == unsafe.StringData(value) {
		h.fatalf("TaintString did not clone")
	}
	if source && (managedName != name || (len(name) > 0 && unsafe.StringData(managedName) == unsafe.StringData(name))) {
		h.fatalf("TaintSourceString name not cloned")
	}
	h.retain(managed, n)
	h.retain(managedName, len(name))
	k, _ := StringKey(managed)
	h.commitRoot(o, plan, ref, k, KindString, uint32(n), charge, ranges.Limit(config.MaxRangeCount), managed, nil)
}

func (h *harness) opTaintBytes(o *mOwner, f *fzIn, mode int) {
	n := f.length()
	c := n + f.length()
	if f.b()%2 == 0 {
		c = n
	}
	value := make([]byte, n, c)
	for i := range value {
		value[i] = byte(i)
	}
	name := ""
	if mode > 0 {
		name = fzString(f, f.length())
	}
	h.retain(value, c)
	src := ranges.SourceID(f.n(8))
	var charge int64
	switch mode {
	case 0:
		charge = sizeClass(c)
	default:
		charge = sizeClass(c) + sizeClass(len(name)) + sizeClass(n)
	}
	inputKey, inputOK := BytesKey(value)
	if inputOK && mode != 2 {
		h.addKey(inputKey)
	}
	plan := newRootPlan{}
	if n >= 2 && n <= MaxRootBytes && c <= MaxRootBytes && len(name) <= MaxRootBytes {
		plan = h.planRoot(o, charge, inputKey, mode == 2, []ranges.Range{{Length: uint32(n), SourceID: src}})
	}
	var managed []byte
	var managedName, managedValue string
	var ref RootRef
	var ok bool
	switch mode {
	case 0:
		managed, ref, ok = o.h.TaintBytes(value, src)
	case 1:
		managed, managedName, managedValue, ref, ok = o.h.TaintSourceBytes(value, name, src)
	case 2:
		managedName, managedValue, ref, ok = o.h.AdoptSourceBytes(value, name, src)
		managed = value
	}
	h.logf("taintBytes mode=%d len=%d cap=%d -> ok=%v ref=%+v", mode, n, c, ok, ref)
	if !h.checkOutcome("TaintBytes", plan, ok, o) {
		if mode != 2 && (len(managed) != n || cap(managed) != c || (n > 0 && unsafe.SliceData(managed) != unsafe.SliceData(value))) {
			h.fatalf("failed TaintBytes did not return input")
		}
		return
	}
	if len(managed) != n || cap(managed) != c || string(managed) != string(value) {
		h.fatalf("TaintBytes changed len/cap/content")
	}
	if mode != 2 && unsafe.SliceData(managed) == unsafe.SliceData(value) {
		h.fatalf("TaintBytes did not clone")
	}
	if mode > 0 && (managedName != name || managedValue != string(value)) {
		h.fatalf("source metadata mismatch")
	}
	h.retain(managed, c)
	k, _ := BytesKey(managed)
	h.commitRoot(o, plan, ref, k, KindBytes, uint32(c), charge, ranges.Limit(config.MaxRangeCount), "", managed)
}

func (h *harness) adoptString(o *mOwner, f *fzIn, value string) {
	span := uint32(len(value))
	set, rs := fzSet(f, span)
	bad := f.b()%10 == 0 && span > 0
	if bad {
		set, rs = fzSet(f, span+16)
	}
	k, keyOK := StringKey(value)
	plan := newRootPlan{}
	if keyOK && len(value) >= 2 && len(value) <= MaxRootBytes && set.ValidFor(span) {
		plan = h.planRoot(o, sizeClass(len(value)), k, true, rs)
	}
	ref, ok := o.h.AdoptString(value, &set)
	h.logf("adoptString len=%d ranges=%d -> ok=%v ref=%+v", len(value), len(rs), ok, ref)
	if !h.checkOutcome("AdoptString", plan, ok, o) {
		return
	}
	h.commitRoot(o, plan, ref, k, KindString, span, sizeClass(len(value)), set.Limit(), value, nil)
}

func (h *harness) adoptBytes(o *mOwner, f *fzIn, value []byte) {
	span := uint32(cap(value))
	set, rs := fzSet(f, span)
	if f.b()%10 == 0 && span > 0 {
		set, rs = fzSet(f, span+16)
	}
	k, keyOK := BytesKey(value)
	plan := newRootPlan{}
	if keyOK && len(value) >= 2 && len(value) <= MaxRootBytes && cap(value) <= MaxRootBytes && set.ValidFor(span) {
		plan = h.planRoot(o, sizeClass(cap(value)), k, true, rs)
	}
	ref, ok := o.h.AdoptBytes(value, &set)
	h.logf("adoptBytes len=%d cap=%d ranges=%d -> ok=%v ref=%+v", len(value), cap(value), len(rs), ok, ref)
	if !h.checkOutcome("AdoptBytes", plan, ok, o) {
		return
	}
	h.commitRoot(o, plan, ref, k, KindBytes, span, sizeClass(cap(value)), set.Limit(), "", value)
}

func (h *harness) opAdoptFresh(o *mOwner, f *fzIn, bytesKind bool) {
	n := f.length()
	if bytesKind {
		c := n + f.n(64)
		v := make([]byte, n, c)
		h.retain(v, c)
		h.adoptBytes(o, f, v)
		return
	}
	v := strings.Clone(fzString(f, n))
	h.retain(v, n)
	h.adoptString(o, f, v)
}

// opReadopt adopts the complete anchor of an existing (live or released) root
// into owner o. This deterministically simulates a numeric address that is
// reused by a new root while stale slots for it still sit in the index.
func (h *harness) opReadopt(o *mOwner, f *fzIn) {
	if len(h.allRoots) == 0 {
		return
	}
	r := h.allRoots[f.n(len(h.allRoots))]
	if r.kind == KindString {
		h.adoptString(o, f, r.str)
		return
	}
	h.adoptBytes(o, f, r.buf[:len(r.buf):cap(r.buf)])
}

// ---- derive / mutation ----

func (h *harness) window(r *mRoot, a, b uint32) Key {
	if r.kind == KindString {
		k, _ := StringKey(r.str[a:b])
		return k
	}
	k, _ := BytesKey(r.buf[:cap(r.buf)][a:b])
	return k
}

func (h *harness) derive(o *mOwner, k Key, ref RootRef, quiet bool) bool {
	pred := false
	var target *mRoot
	var off uint32
	if o.alive && validKey(k) && ref.ID < MaxRootsPerOwner {
		if r := o.roots[ref.ID]; r != nil && r.valid && r.gen == ref.Generation {
			if o2, in := inWindow(k.Pointer, k.Length, r.base, r.span); in {
				ok, needProbe := h.predictPut(o, k, r, len(r.windows))
				pred = ok && (!needProbe || h.probeHasEmpty(k))
				target, off = r, o2
			}
		}
	}
	ok := o.h.Derive(k, ref)
	if !quiet {
		h.logf("derive owner=%d key=%x+%d ref=%+v -> ok=%v", o.idx, k.Pointer, k.Length, ref, ok)
	}
	if ok != pred {
		h.fatalf("Derive ok=%v, model predicted %v (key=%+v ref=%+v)", ok, pred, k, ref)
	}
	if ok {
		h.applyPut(o, k, target, off)
	} else if validKey(k) {
		h.addKey(k)
	}
	return ok
}

func (h *harness) opDerive(o *mOwner, f *fzIn, mode int) {
	var pool []*mRoot
	switch mode {
	case 0:
		pool = o.list
	default:
		pool = h.allRoots
	}
	if len(pool) == 0 {
		return
	}
	r := pool[f.n(len(pool))]
	if r.span == 0 {
		return
	}
	a := uint32(f.n(int(r.span)))
	b := a + 1 + uint32(f.n(int(r.span-a)))
	ref := RootRef{ID: r.id, Generation: r.callerGen}
	if mode == 2 {
		ref.Generation-- // stale caller reference
	}
	if r.kind == KindBytes && f.b()%4 == 0 && b <= uint32(len(r.buf)) {
		// a length-zero or tombstone-like key must be rejected
		h.derive(o, Key{Pointer: 0, Length: b - a, Kind: KindBytes}, ref, false)
	}
	h.derive(o, h.window(r, a, b), ref, false)
}

func (h *harness) opBulkDerive(o *mOwner, f *fzIn) {
	if len(o.list) == 0 {
		return
	}
	r := o.list[f.n(len(o.list))]
	count := f.n(300)
	width := uint32(1 + f.n(4))
	ref := RootRef{ID: r.id, Generation: r.callerGen}
	done := 0
	for i := 0; i < count && uint32(i)+width <= r.span; i++ {
		if h.derive(o, h.window(r, uint32(i), uint32(i)+width), ref, true) {
			done++
		}
	}
	h.logf("bulkDerive root=%d count=%d width=%d -> %d ok (quota=%d)", r.id, count, width, done, len(r.windows))
}

func (h *harness) opBulkTaint(o *mOwner, f *fzIn) {
	count := f.n(600)
	n := f.length()
	h.logf("bulkTaint count=%d len=%d", count, n)
	for i := 0; i < count && h.kept < fzMaxBytes; i++ {
		value := fzString(f, n)
		plan := newRootPlan{}
		if n >= 2 && n <= MaxRootBytes {
			plan = h.planRoot(o, sizeClass(n), Key{}, false, []ranges.Range{{Length: uint32(n)}})
		}
		managed, ref, ok := o.h.TaintString(value, 0)
		if !h.checkOutcome("bulk TaintString", plan, ok, o) {
			continue
		}
		h.retain(managed, n)
		k, _ := StringKey(managed)
		h.commitRoot(o, plan, ref, k, KindString, uint32(n), sizeClass(n), ranges.Limit(config.MaxRangeCount), managed, nil)
	}
}

// opFlood drives one owner to its request value limit with many one-byte
// windows over 260-byte roots, which also exercises the per-root quota, the
// process value limit, probe exhaustion, rollback and shard compaction.
func (h *harness) opFlood(o *mOwner, f *fzIn) {
	target := RequestValueLimit + 8 - f.n(64)
	roots, derived := 0, 0
	for attempts := 0; o.values < target && attempts < 64 && h.kept < fzMaxBytes; attempts++ {
		value := strings.Repeat("f", 260)
		plan := h.planRoot(o, sizeClass(260), Key{}, false, []ranges.Range{{Length: 260, SourceID: ranges.SourceID(attempts)}})
		managed, ref, ok := o.h.TaintString(value, ranges.SourceID(attempts))
		if !h.checkOutcome("flood TaintString", plan, ok, o) {
			if o.values >= RequestValueLimit || h.processValues() >= ProcessValueLimit || !o.alive {
				break
			}
			continue
		}
		roots++
		h.retain(managed, 260)
		k, _ := StringKey(managed)
		h.commitRoot(o, plan, ref, k, KindString, 260, sizeClass(260), ranges.Limit(config.MaxRangeCount), managed, nil)
		r := o.roots[ref.ID]
		for i := uint32(0); i < MaxValuesPerRoot+1; i++ {
			if h.derive(o, h.window(r, i, i+1), ref, true) {
				derived++
			}
		}
	}
	h.logf("flood owner=%d roots=%d derived=%d values=%d process=%d", o.idx, roots, derived, o.values, h.processValues())
}

func nextGen(g uint32) uint32 {
	g++
	if g == 0 {
		g = 1
	}
	return g
}

func (h *harness) opMutate(o *mOwner, f *fzIn) {
	var pool []*mRoot
	if f.b()%4 == 0 {
		pool = o.list
	} else {
		for _, r := range o.list {
			if r.kind == KindBytes {
				pool = append(pool, r)
			}
		}
	}
	if len(pool) == 0 {
		return
	}
	r := pool[f.n(len(pool))]
	ref := RootRef{ID: r.id, Generation: r.callerGen}
	if f.b()%8 == 0 {
		ref.Generation--
	}
	var value []byte
	switch f.b() % 6 {
	case 0:
		if r.buf != nil && cap(r.buf) > 1 {
			value = r.buf[1:cap(r.buf)]
		}
	case 1:
		value = make([]byte, 4, 8)
		h.retain(value, 8)
	case 2:
		if r.buf != nil && cap(r.buf) > 1 {
			value = r.buf[: 1 : cap(r.buf)-1]
		}
	default:
		if r.buf != nil {
			value = r.buf[:f.n(cap(r.buf)+1):cap(r.buf)]
		}
	}
	if len(value) > 0 {
		value[0]++ // the application mutation
	}
	var set *ranges.Set
	var rs []ranges.Range
	if f.b()%8 != 0 {
		s, stored := fzSet(f, uint32(cap(value)))
		if f.b()%10 == 0 {
			s, stored = fzSet(f, uint32(cap(value))+16)
		}
		set, rs = &s, stored
	}

	// Prediction.
	pred := false
	claimed := false
	var key Key
	var prepared []ranges.Range
	var preparedOverflow bool
	if ref.ID < MaxRootsPerOwner && o.alive {
		if cur := o.roots[ref.ID]; cur == r && r.gen == ref.Generation {
			claimed = true
			var keyOK bool
			key, keyOK = BytesKey(value)
			if set != nil && len(value) > 0 && len(value) <= MaxRootBytes && cap(value) <= MaxRootBytes && keyOK && set.ValidFor(uint32(cap(value))) {
				prepared = rs
				if len(rs) > GuaranteedRanges {
					if OverflowBlocks-h.held > 0 {
						preparedOverflow = true
					} else {
						prepared = rs[:GuaranteedRanges]
					}
				}
				if r.kind == KindBytes && r.base == key.Pointer && r.span == uint32(cap(value)) {
					pred = true
				}
			}
		}
	}
	if claimed {
		r.gen = nextGen(r.gen)
		r.valid = false
		h.dropRootWindows(r)
		if pred {
			if r.overflow {
				h.held--
			}
			r.overflow = preparedOverflow
			if preparedOverflow {
				h.held++
			}
			r.rs = prepared
			r.limit = set.Limit()
			r.buf = value
			r.valid = true
			ok, needProbe := h.predictPut(o, key, r, 0)
			pred = ok && (!needProbe || h.probeHasEmpty(key))
		}
	}
	newRef, ok := o.h.PublishBytesMutation(ref, value, set)
	h.logf("mutate root=%d ref=%+v len=%d cap=%d ranges=%d -> ok=%v new=%+v (claimed=%v)", r.id, ref, len(value), cap(value), len(rs), ok, newRef, claimed)
	if ok != pred {
		h.fatalf("PublishBytesMutation ok=%v, model predicted %v", ok, pred)
	}
	if ok {
		if newRef != (RootRef{ID: r.id, Generation: r.gen}) {
			h.fatalf("mutation ref=%+v want id=%d gen=%d", newRef, r.id, r.gen)
		}
		r.callerGen = r.gen
		h.applyPut(o, key, r, 0)
	}
}

// ---- stale handles ----

func (h *harness) opStale(f *fzIn) {
	if len(h.dead) == 0 {
		return
	}
	o := h.dead[f.n(len(h.dead))]
	value := fzString(f, 8)
	managed, _, ok := o.h.TaintString(value, 0)
	if ok || unsafe.StringData(managed) != unsafe.StringData(value) {
		h.fatalf("stale owner TaintString published")
	}
	if len(h.allRoots) > 0 {
		r := h.allRoots[f.n(len(h.allRoots))]
		if o.h.Derive(h.window(r, 0, r.span), RootRef{ID: r.id, Generation: r.callerGen}) {
			h.fatalf("stale owner Derive published")
		}
		if r.kind == KindBytes {
			set, _ := fzSet(f, r.span)
			if _, ok := o.h.PublishBytesMutation(RootRef{ID: r.id, Generation: r.callerGen}, r.buf, &set); ok {
				h.fatalf("stale owner mutation published")
			}
		}
	}
	if BindObject(o.h, h.objs[0], BindingURL) {
		h.fatalf("stale owner bound object")
	}
	var in ranges.Set
	if o.h.UpdateWriter(h.builders[0], WriterStringBuilder, WriterView{}, WriterView{Pointer: 1, Length: 2, Capacity: 2}, &in, 2, 2) {
		h.fatalf("stale owner updated writer")
	}
	h.logf("stale ops on idx=%d gen=%d", o.idx, o.gen)
}

// ---- bindings ----

func (h *harness) bind(o *mOwner, obj *fzObj, kind BindingKind, dynamic bool) bool {
	ptr := uintptr(unsafe.Pointer(obj))
	pred := false
	if o.alive && kind != BindingInvalid {
		if old, found := o.bindings[ptr]; found {
			pred = !(old != BindingReader && kind == BindingReader && o.readers >= MaxReaderBindings)
		} else {
			pred = o.bindN < MaxBindings && !(kind == BindingReader && o.readers >= MaxReaderBindings)
		}
	}
	var ok bool
	if dynamic {
		ok = BindObjectValue(o.h, any(obj), kind)
	} else {
		ok = BindObject(o.h, obj, kind)
	}
	if ok != pred {
		h.fatalf("bind kind=%d ok=%v, model predicted %v (bindings=%d readers=%d)", kind, ok, pred, o.bindN, o.readers)
	}
	if ok {
		old, found := o.bindings[ptr]
		if !found {
			o.bindN++
		}
		if kind == BindingReader && (!found || old != BindingReader) {
			o.readers++
		}
		if found && old == BindingReader && kind != BindingReader {
			o.readers--
		}
		o.bindings[ptr] = kind
	}
	return ok
}

func (h *harness) opBind(o *mOwner, f *fzIn) {
	obj := h.objs[f.n(len(h.objs))]
	kind := BindingKind(f.n(3))
	ok := h.bind(o, obj, kind, f.b()%2 == 0)
	h.logf("bind owner=%d obj=%p kind=%d -> %v", o.idx, obj, kind, ok)
}

func (h *harness) opBulkBind(o *mOwner, f *fzIn) {
	count := f.n(300)
	kind := BindingKind(1 + f.n(2))
	n := 0
	for i := 0; i < count; i++ {
		obj := &fzObj{}
		h.objs = append(h.objs, obj)
		if h.bind(o, obj, kind, false) {
			n++
		}
	}
	h.logf("bulkBind owner=%d count=%d kind=%d -> %d", o.idx, count, kind, n)
}

func (h *harness) checkObject(obj *fzObj, kind BindingKind, width int) {
	ptr := uintptr(unsafe.Pointer(obj))
	var want []*mOwner
	for i := 0; i < MaxOwners; i++ {
		for _, o := range h.aliveOwners() {
			if int(o.idx) == i {
				if k, found := o.bindings[ptr]; found && (kind == BindingInvalid || k == kind) {
					want = append(want, o)
				}
			}
		}
	}
	out := make([]OwnerRef, width)
	var n int
	if kind == BindingInvalid {
		n = LookupObject(h.s, obj, out)
	} else {
		n = LookupObjectValue(h.s, any(obj), kind, out)
	}
	if n != min(len(want), width) {
		h.fatalf("LookupObject kind=%d n=%d want %d", kind, n, min(len(want), width))
	}
	for i := 0; i < n; i++ {
		idx, gen, id, ok := out[i].Identity()
		if !ok || idx != want[i].idx || gen != want[i].gen || id != want[i].id || out[i].Kind != want[i].bindings[ptr] {
			h.fatalf("LookupObject[%d]=(%d,%d,%d,%v,kind=%d) want owner %d", i, idx, gen, id, ok, out[i].Kind, want[i].idx)
		}
	}
}

// ---- writers (strings.Builder kind; synthetic views) ----

func (o *mOwner) writerIndex(ptr uintptr) int {
	for i, w := range o.writers {
		if w.ptr == ptr {
			return i
		}
	}
	return -1
}

func (o *mOwner) removeWriter(i int) {
	if i >= 0 {
		o.writers = append(o.writers[:i], o.writers[i+1:]...)
	}
}

func fzView(f *fzIn) WriterView {
	l := uint32(f.n(200))
	c := l + uint32(f.n(200))
	if f.b()%16 == 0 {
		c = MaxRootBytes + 1
	}
	return WriterView{Pointer: 0x100000 + uintptr(f.n(1<<12)), Length: l, Capacity: c}
}

func (h *harness) opUpdateWriter(o *mOwner, f *fzIn) {
	obj := h.builders[f.n(len(h.builders))]
	ptr := uintptr(unsafe.Pointer(obj))
	idx := o.writerIndex(ptr)
	before := fzView(f)
	if idx >= 0 && f.b()%4 != 0 {
		before = o.writers[idx].view
	}
	written := uint32(f.n(64))
	inputLen := written + uint32(f.n(8))
	if f.b()%12 == 0 {
		written = inputLen + 1
	}
	var input *ranges.Set
	if f.b()%3 != 0 && inputLen > 0 {
		s, _ := fzSet(f, inputLen)
		input = &s
	}
	after := WriterView{Pointer: before.Pointer + uintptr(f.n(2)), Length: before.Length + written}
	after.Capacity = max(after.Length, before.Capacity) + uint32(f.length())
	if f.b()%12 == 0 {
		after.Length++
	}

	// Prediction mirrors writer.go's documented admission rules.
	pred := false
	func() {
		if !o.alive {
			return
		}
		if !validWriterView(before) || !validWriterView(after) || written > inputLen || uint64(before.Length)+uint64(written) != uint64(after.Length) {
			o.removeWriter(idx)
			return
		}
		if idx >= 0 && o.writers[idx].view != before {
			o.removeWriter(idx)
			idx = -1
		}
		var ws ranges.Set
		if input != nil {
			if !input.ValidFor(inputLen) || !ranges.Slice(&ws, input.Limit(), input, inputLen, 0, written).Valid {
				o.removeWriter(idx)
				return
			}
		}
		if idx < 0 && ws.Len() == 0 {
			pred = true
			return
		}
		var current *ranges.Set
		limit := ws.Limit()
		if idx >= 0 {
			current = &o.writers[idx].set
			limit = current.Limit()
		}
		var next ranges.Set
		outcome := ranges.Concat(&next, limit, current, before.Length, setOrNil(&ws), written)
		if !outcome.Valid || next.Len() == 0 || !next.ValidFor(after.Length) {
			o.removeWriter(idx)
			pred = outcome.Valid
			return
		}
		if idx < 0 {
			if len(o.writers) >= MaxWriters {
				return
			}
			o.writers = append(o.writers, &mWriter{ptr: ptr})
			idx = len(o.writers) - 1
		}
		w := o.writers[idx]
		desired := int64(0)
		if after.Capacity > 0 {
			desired = sizeClass(int(after.Capacity))
		}
		if delta := desired - w.charge; delta > 0 && (o.charged()+delta > RequestRootBytes || h.processCharged()+delta > ProcessRootBytes) {
			o.removeWriter(idx)
			return
		}
		w.charge, w.view, w.set = desired, after, next
		pred = true
	}()
	ok := o.h.UpdateWriter(obj, WriterStringBuilder, before, after, input, inputLen, written)
	h.logf("updateWriter owner=%d before=%+v after=%+v written=%d/%d -> %v", o.idx, before, after, written, inputLen, ok)
	if ok != pred {
		h.fatalf("UpdateWriter ok=%v, model predicted %v", ok, pred)
	}
}

func (h *harness) opTruncateWriter(o *mOwner, f *fzIn) {
	obj := h.builders[f.n(len(h.builders))]
	ptr := uintptr(unsafe.Pointer(obj))
	idx := o.writerIndex(ptr)
	before := fzView(f)
	if idx >= 0 && f.b()%4 != 0 {
		before = o.writers[idx].view
	}
	after := before
	after.Length = uint32(f.n(int(before.Length) + 2))
	after.Capacity = max(after.Length, uint32(f.n(int(before.Capacity)+2)))
	pred := false
	func() {
		if !o.alive {
			return
		}
		if !validWriterView(before) || !validWriterView(after) || after.Length > before.Length {
			o.removeWriter(idx)
			return
		}
		if idx < 0 {
			pred = true
			return
		}
		w := o.writers[idx]
		if w.view != before {
			o.removeWriter(idx)
			return
		}
		var next ranges.Set
		if !ranges.Slice(&next, w.set.Limit(), &w.set, before.Length, 0, after.Length).Valid || next.Len() == 0 {
			o.removeWriter(idx)
			pred = true
			return
		}
		desired := int64(0)
		if after.Capacity > 0 {
			desired = sizeClass(int(after.Capacity))
		}
		if delta := desired - w.charge; delta > 0 && (o.charged()+delta > RequestRootBytes || h.processCharged()+delta > ProcessRootBytes) {
			o.removeWriter(idx)
			return
		}
		w.charge, w.view, w.set = desired, after, next
		pred = true
	}()
	ok := o.h.TruncateWriter(obj, WriterStringBuilder, before, after)
	h.logf("truncateWriter owner=%d before=%+v after=%+v -> %v", o.idx, before, after, ok)
	if ok != pred {
		h.fatalf("TruncateWriter ok=%v, model predicted %v", ok, pred)
	}
}

func (h *harness) opResetWriter(o *mOwner, f *fzIn) {
	obj := h.builders[f.n(len(h.builders))]
	ptr := uintptr(unsafe.Pointer(obj))
	if f.b()%2 == 0 {
		h.s.InvalidateWriterPointer(ptr)
		for _, a := range h.aliveOwners() {
			a.removeWriter(a.writerIndex(ptr))
		}
		h.logf("invalidateWriterPointer %p", obj)
		return
	}
	ok := o.h.ResetWriter(obj, WriterStringBuilder)
	h.logf("resetWriter owner=%d -> %v", o.idx, ok)
	if ok != o.alive {
		h.fatalf("ResetWriter ok=%v, owner alive=%v", ok, o.alive)
	}
	if ok {
		o.removeWriter(o.writerIndex(ptr))
	}
}

func (h *harness) checkWriters() {
	for _, o := range h.aliveOwners() {
		for _, obj := range h.builders {
			ptr := uintptr(unsafe.Pointer(obj))
			idx := o.writerIndex(ptr)
			var dst ranges.Set
			if idx < 0 {
				if o.h.SnapshotWriter(obj, WriterStringBuilder, WriterView{Pointer: 1, Length: 1, Capacity: 1}, &dst) {
					h.fatalf("SnapshotWriter found untracked writer")
				}
				continue
			}
			w := o.writers[idx]
			if !o.h.SnapshotWriter(obj, WriterStringBuilder, w.view, &dst) || !equalRanges(setSlice(&dst), setSlice(&w.set)) {
				h.fatalf("SnapshotWriter mismatch: got %v want %v", setSlice(&dst), setSlice(&w.set))
			}
		}
	}
	for _, obj := range h.builders {
		ptr := uintptr(unsafe.Pointer(obj))
		var want []*mOwner
		for i := 0; i < MaxOwners; i++ {
			for _, o := range h.aliveOwners() {
				if int(o.idx) == i && o.writerIndex(ptr) >= 0 {
					want = append(want, o)
				}
			}
		}
		out := make([]WriterRef, MaxSnapshotOwners)
		n := LookupWriterValue(h.s, obj, WriterStringBuilder, WriterView{}, out)
		if n != min(len(want), len(out)) {
			h.fatalf("LookupWriterValue n=%d want %d", n, len(want))
		}
		for i := 0; i < n; i++ {
			idx, gen, ok := out[i].Identity()
			if !ok || idx != want[i].idx || gen != want[i].gen {
				h.fatalf("LookupWriterValue[%d] mismatch", i)
			}
		}
	}
}

// ---- saturation ----

func (h *harness) opSaturateOwners() {
	free := 0
	for _, b := range h.busy {
		if !b {
			free++
		}
	}
	var extra []*Owner
	for i := 0; i < free; i++ {
		o := h.s.Acquire()
		if o.Disabled() {
			h.fatalf("saturate: acquire %d/%d disabled", i, free)
		}
		idx, _ := o.Index()
		h.slotGen[idx]++
		h.lastID++
		extra = append(extra, o)
	}
	drops := h.s.AcquireDrops()
	if !h.s.Acquire().Disabled() || h.s.AcquireDrops() != drops+1 {
		h.fatalf("saturate: acquire beyond %d owners was not dropped", MaxOwners)
	}
	for _, o := range extra {
		o.Finish()
	}
	h.logf("saturateOwners free=%d", free)
}

// ---- verification ----

type expEntry struct {
	o  *mOwner
	r  *mRoot
	rs []ranges.Range
}

func (h *harness) expected(k Key) []expEntry {
	var out []expEntry
	for _, o := range h.aliveOwners() {
		w := h.windows[wKey{o, k}]
		if w == nil {
			continue
		}
		if !w.root.valid || w.root.owner != o {
			h.fatalf("model window points to invalid root")
		}
		if len(w.root.rs) == 0 {
			continue
		}
		out = append(out, expEntry{o, w.root, sliceRanges(w.root.rs, w.off, w.off+k.Length)})
	}
	return out
}

func (h *harness) checkKey(k Key, save bool) {
	exp := h.expected(k)
	var snap Snapshot
	if !h.s.Lookup(k, &snap) {
		h.fatalf("Lookup reported contention in a single-threaded sequence")
	}
	if len(exp) > 0 && !h.s.MayContain(k) {
		h.fatalf("MayContain false for a live key %+v", k)
	}
	crowded := h.physicalMatches(k) > MaxSnapshotOwners
	if crowded && snap.Len() < min(len(exp), MaxSnapshotOwners) {
		h.crowded++ // stale slots consumed fanout windows (see store-fuzz-F1)
	} else if snap.Len() != min(len(exp), MaxSnapshotOwners) {
		got := []string{}
		for i := 0; i < snap.Len(); i++ {
			e, _ := snap.At(i)
			got = append(got, fmt.Sprintf("owner=%d root=%+v ranges=%v", e.OwnerIndex, e.Root, setSlice(&e.Ranges)))
		}
		h.fatalf("Lookup(%x+%d kind=%d) len=%d want %d; got %v", k.Pointer, k.Length, k.Kind, snap.Len(), len(exp), got)
	}
	for i := 0; i < snap.Len(); i++ {
		e, _ := snap.At(i)
		var match *expEntry
		for j := range exp {
			if exp[j].o.idx == e.OwnerIndex {
				match = &exp[j]
			}
		}
		if match == nil {
			h.fatalf("Lookup returned unexpected owner %d", e.OwnerIndex)
		}
		if e.OwnerID != match.o.id || e.OwnerGen != match.o.gen || e.Root != (RootRef{ID: match.r.id, Generation: match.r.gen}) {
			h.fatalf("Lookup entry identity %+v/%+v, want owner id=%d gen=%d root=%d/%d", e.OwnerID, e.Root, match.o.id, match.o.gen, match.r.id, match.r.gen)
		}
		if !equalRanges(setSlice(&e.Ranges), match.rs) {
			h.fatalf("Lookup ranges %v want %v (root ranges %v)", setSlice(&e.Ranges), match.rs, match.r.rs)
		}
		if e.Ranges.Limit() != match.r.limit {
			h.fatalf("Lookup limit %d want %d", e.Ranges.Limit(), match.r.limit)
		}
		handle, ok := e.Handle(h.s)
		if !ok || handle.ID() != match.o.id {
			h.fatalf("Entry.Handle invalid for live entry")
		}
		if save && len(match.o.entries) < 4 {
			match.o.entries = append(match.o.entries, *e)
		}
	}
}

func (h *harness) physicalMatches(k Key) int {
	hash := keyHash(k)
	sh := &h.s.shards[shardIndex(hash)]
	start := initialSlot(hash)
	n := 0
	for p := 0; p < ProbeLimit; p++ {
		slot := &sh.slots[(start+uint8(p))%SlotsPerShard]
		if slot.pointer == 0 {
			break
		}
		if slot.pointer == k.Pointer && slot.length == k.Length && slot.kind == k.Kind {
			n++
		}
	}
	return n
}

func (h *harness) checkSample(touched int) {
	n := len(h.keys)
	if n == 0 {
		return
	}
	for i := max(0, n-touched); i < n; i++ {
		h.checkKey(h.keys[i], i == n-1)
	}
	for i := 0; i < 24 && i < n; i++ {
		h.sample = (h.sample + 7919) % n
		h.checkKey(h.keys[h.sample], false)
	}
}

func (h *harness) checkAllKeys() {
	for _, k := range h.keys {
		h.checkKey(k, false)
	}
}

func (h *harness) checkGlobal() {
	var pc int64
	pv, writers := 0, 0
	for _, o := range h.aliveOwners() {
		rec := o.h.owner
		oc := o.charged()
		if o.h.Charged() != oc || oc > RequestRootBytes {
			h.fatalf("owner %d charged=%d model=%d", o.idx, o.h.Charged(), oc)
		}
		if int(o.h.Values()) != o.values || o.values > RequestValueLimit || o.values < 0 {
			h.fatalf("owner %d values=%d model=%d", o.idx, o.h.Values(), o.values)
		}
		if int(rec.rootCount.Load()) != len(o.roots) || len(o.roots) > MaxRootsPerOwner {
			h.fatalf("owner %d rootCount=%d model=%d", o.idx, rec.rootCount.Load(), len(o.roots))
		}
		if int(rec.bindings.count) != o.bindN || int(rec.bindings.readerCount) != o.readers || o.bindN > MaxBindings || o.readers > MaxReaderBindings {
			h.fatalf("owner %d bindings=%d/%d readers=%d/%d", o.idx, rec.bindings.count, o.bindN, rec.bindings.readerCount, o.readers)
		}
		if int(rec.writerCount) != len(o.writers) || len(o.writers) > MaxWriters {
			h.fatalf("owner %d writers=%d model=%d", o.idx, rec.writerCount, len(o.writers))
		}
		for _, r := range o.roots {
			quota := rec.roots[r.id].valueQuota.Load()
			if rec.roots[r.id].generation.Load() != r.gen {
				h.fatalf("root %d generation %d model %d", r.id, rec.roots[r.id].generation.Load(), r.gen)
			}
			if r.valid && (uint32(quota>>32) != r.gen || int(uint32(quota)) != len(r.windows)) {
				h.fatalf("root %d quota gen=%d count=%d, model gen=%d count=%d", r.id, quota>>32, uint32(quota), r.gen, len(r.windows))
			}
		}
		pc += oc
		pv += o.values
		writers += len(o.writers)
	}
	if h.s.ProcessCharged() != pc || pc > ProcessRootBytes {
		h.fatalf("process charged=%d model=%d", h.s.ProcessCharged(), pc)
	}
	if int(h.s.ProcessValues()) != pv || pv > ProcessValueLimit {
		h.fatalf("process values=%d model=%d", h.s.ProcessValues(), pv)
	}
	if int(h.opActive.Load()) != pv {
		h.fatalf("operator mirror=%d values=%d", h.opActive.Load(), pv)
	}
	if int(h.s.writerStates.Load()) != writers || int(h.wrActive.Load()) != writers {
		h.fatalf("writer states=%d mirror=%d model=%d", h.s.writerStates.Load(), h.wrActive.Load(), writers)
	}
	if int(h.s.overflowN) != OverflowBlocks-h.held {
		h.fatalf("overflow free=%d model=%d", h.s.overflowN, OverflowBlocks-h.held)
	}
	for i := range h.s.shards {
		sh := &h.s.shards[i]
		tomb := 0
		for j := range sh.slots {
			if sh.slots[j].pointer == tombstone {
				tomb++
			}
		}
		if tomb != int(sh.tombstones) {
			h.fatalf("shard %d tombstones counter=%d actual=%d", i, sh.tombstones, tomb)
		}
		if sh.probeMax > ProbeLimit {
			h.fatalf("shard %d probeMax=%d", i, sh.probeMax)
		}
	}
}

func runStoreSequence(t testing.TB, data []byte) { runStoreSequenceHarness(t, data) }

func runStoreSequenceHarness(t testing.TB, data []byte) *harness {
	h := newHarness(t)
	f := &fzIn{data: data}
	for op := 0; op < fzMaxOps && f.more() && h.kept < fzMaxBytes; op++ {
		code := f.b() % 27
		touchedBefore := len(h.keys)
		switch code {
		case 0:
			h.acquire(f.n(fzHandles))
		case 1:
			if o := h.slots[f.n(fzHandles)]; o != nil {
				h.finish(o)
				h.checkAllKeys()
			}
		case 2:
			h.opTaintString(h.owner(f), f, false)
		case 3:
			h.opTaintString(h.owner(f), f, true)
		case 4:
			h.opTaintBytes(h.owner(f), f, 0)
		case 5:
			h.opTaintBytes(h.owner(f), f, 1)
		case 6:
			h.opTaintBytes(h.owner(f), f, 2)
		case 7:
			h.opAdoptFresh(h.owner(f), f, false)
		case 8:
			h.opAdoptFresh(h.owner(f), f, true)
		case 9, 10:
			h.opReadopt(h.owner(f), f)
		case 11, 12:
			h.opDerive(h.owner(f), f, 0)
		case 13:
			h.opDerive(h.owner(f), f, 1+f.n(2))
		case 14, 15:
			h.opMutate(h.owner(f), f)
		case 16:
			h.opBulkTaint(h.owner(f), f)
		case 17:
			h.opBulkDerive(h.owner(f), f)
		case 18:
			h.opStale(f)
		case 19:
			h.opBind(h.owner(f), f)
		case 20:
			h.opBulkBind(h.owner(f), f)
		case 21:
			h.checkObject(h.objs[f.n(len(h.objs))], BindingKind(f.n(3)), 1+f.n(4))
		case 22:
			h.opUpdateWriter(h.owner(f), f)
		case 23:
			h.opTruncateWriter(h.owner(f), f)
		case 24:
			h.opResetWriter(h.owner(f), f)
		case 25:
			h.opSaturateOwners()
		case 26:
			h.opFlood(h.owner(f), f)
		}
		h.checkGlobal()
		h.checkSample(len(h.keys) - touchedBefore + 1)
		if code >= 22 {
			h.checkWriters()
		}
	}
	h.checkAllKeys()
	h.checkWriters()
	for _, o := range h.slots {
		if o != nil {
			h.finish(o)
		}
	}
	h.checkGlobal()
	h.checkAllKeys()
	if h.s.ProcessCharged() != 0 || h.s.ProcessValues() != 0 || h.s.overflowN != OverflowBlocks || h.s.writerStates.Load() != 0 || h.opActive.Load() != 0 {
		h.fatalf("store not drained: charged=%d values=%d overflowFree=%d writers=%d", h.s.ProcessCharged(), h.s.ProcessValues(), h.s.overflowN, h.s.writerStates.Load())
	}
	return h
}

func FuzzStoreSequence(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, 0, 0, 20, 1, 11, 0, 0, 3, 0, 1, 0, 1, 0, 0})
	f.Add([]byte{4, 0, 0, 30, 0, 0, 2, 14, 0, 0, 0, 0, 0, 5, 2, 3, 1, 5, 7, 11, 14, 0, 0, 1, 0, 3, 1, 1, 0, 0})
	f.Add([]byte{16, 0, 0, 200, 1, 222, 17, 0, 0, 0, 0, 200, 1, 1, 0, 0, 0})
	f.Add([]byte{8, 0, 0, 30, 20, 0, 0, 60, 0, 0, 0, 9, 1, 0, 0, 0, 0, 0, 0, 9, 1, 0, 0, 0, 0, 0, 1, 0, 0, 10, 2, 0, 0, 0})
	f.Add([]byte{22, 0, 0, 0, 0, 3, 0, 5, 0, 1, 10, 0, 3, 0, 1, 0, 0, 3, 23, 0, 0, 0, 0, 1, 0, 2, 0, 24, 0, 0, 0, 1, 25, 18, 0, 0})
	f.Add([]byte{20, 0, 0, 44, 1, 1, 20, 0, 0, 20, 0, 2, 19, 0, 0, 3, 0, 1, 0, 0, 21, 0, 0, 1, 0, 3, 0})
	// flood four owners, finish them, flood again (limits, probes, compaction)
	f.Add([]byte{26, 0, 0, 0, 0, 26, 1, 0, 0, 0, 26, 2, 0, 0, 0, 26, 3, 0, 0, 0, 26, 4, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 2, 0, 26, 0, 0, 0, 0, 26, 1, 0, 0, 0, 26, 2, 0, 0, 0, 2, 5, 0, 20, 17, 5, 0, 0, 0, 200, 1, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		runStoreSequence(t, data)
	})
}

// TestStoreSequenceFlood deterministically saturates owner and process value
// limits, then churns owners so stale slots are reclaimed and compacted.
func TestStoreSequenceFlood(t *testing.T) {
	data := []byte{}
	for round := 0; round < 3; round++ {
		for slot := byte(0); slot < 5; slot++ {
			data = append(data, 0, slot, 0, 26, slot, 0, byte(round*7), 0)
		}
		for slot := byte(0); slot < 5; slot++ {
			data = append(data, 1, slot, 0)
		}
	}
	h := runStoreSequenceHarness(t, data)
	stats := h.s.Stats()
	t.Logf("compactions=%d aborts=%d probeSkips=%d crowded=%d maxProbe=%d avgProbe=%.2f", stats.Compactions, stats.CompactAborts, h.probeSkip, h.crowded, stats.MaxProbe, stats.AverageProbe)
	for _, line := range h.trace {
		if strings.HasPrefix(line, "flood") {
			t.Log(line)
		}
	}
}

// TestStoreSequenceSeeds replays deterministic pseudo-random sequences so the
// model runs under plain `go test` as well.
func TestStoreSequenceSeeds(t *testing.T) {
	state := uint64(0x9e3779b97f4a7c15)
	for i := 0; i < 300; i++ {
		data := make([]byte, 1500)
		for j := range data {
			state ^= state << 13
			state ^= state >> 7
			state ^= state << 17
			data[j] = byte(state)
		}
		runStoreSequence(t, data)
	}
}
