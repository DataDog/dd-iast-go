// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtimebridge

import (
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// fake is a store stand-in: a filter and a confirm function that reports the
// values in tainted as tainted.
type fake struct {
	filter   Filter
	tainted  map[uintptr]ConfirmResult
	confirms atomic.Int32
	panics   bool
}

func (f *fake) confirm(p uintptr, _ uint32) ConfirmResult {
	f.confirms.Add(1)
	if f.panics {
		panic("confirm failure")
	}
	return f.tainted[p]
}

// mark sets the filter buckets of p, as an indexed root in its granule does.
func (f *fake) mark(p uintptr) { f.filter[bucketS(p)].Add(1) }

func (f *fake) markString(s string, result ConfirmResult) {
	p := stringPointer(s)
	f.mark(p)
	f.tainted[p] = result
}

// install replaces the process binding, the switch word and the callbacks for
// one test, and restores them after the test.
func install(t *testing.T, f *fake, s2s bool, c *Callbacks) *Gate {
	t.Helper()
	previousBinding := binding.Swap(nil)
	previousS2S := atomic.SwapUint32(&s2sGate, 0)
	previousGate := atomic.LoadUint32(&gate)
	previousCallbacks := callbacks.Swap(c)
	t.Cleanup(func() {
		binding.Store(previousBinding)
		atomic.StoreUint32(&s2sGate, previousS2S)
		atomic.StoreUint32(&gate, previousGate)
		callbacks.Store(previousCallbacks)
	})
	if f == nil {
		return nil
	}
	g, ok := Bind(&Binding{Filter: &f.filter, Confirm: f.confirm}, Options{StringToSlice: s2s})
	require.True(t, ok)
	return g
}

func newFake() *fake { return &fake{tainted: map[uintptr]ConfirmResult{}} }

func TestBindInstallsOneBinding(t *testing.T) {
	install(t, nil, false, nil)
	f := newFake()
	_, ok := Bind(nil, Options{})
	require.False(t, ok)
	_, ok = Bind(&Binding{Filter: &f.filter}, Options{})
	require.False(t, ok, "a binding without confirm")
	_, ok = Bind(&Binding{Confirm: f.confirm}, Options{})
	require.False(t, ok, "a binding without filter")
	require.False(t, Bound())
	require.False(t, StringToSliceEnabled())

	g, ok := Bind(&Binding{Filter: &f.filter, Confirm: f.confirm}, Options{StringToSlice: true})
	require.True(t, ok)
	require.True(t, Bound())
	require.True(t, StringToSliceEnabled())

	other := newFake()
	second, ok := Bind(&Binding{Filter: &other.filter, Confirm: other.confirm}, Options{})
	require.False(t, ok, "a second binding is refused")
	require.Nil(t, second)
	require.Same(t, &f.filter, binding.Load().Filter, "the first binding stays")
	require.True(t, StringToSliceEnabled(), "a refused binding does not change the switch word")

	require.Zero(t, GateValue())
	g.Add(2)
	require.Equal(t, uint32(2), GateValue())
	g.Add(-2)
	require.Zero(t, GateValue())
	var none *Gate
	none.Add(1)
	require.Zero(t, GateValue())
}

func TestBindSwitchOff(t *testing.T) {
	install(t, newFake(), false, nil)
	require.False(t, StringToSliceEnabled())
}

func TestConcatPre(t *testing.T) {
	require.False(t, concatPre([]string{"a", "b"}), "no binding")
	f := newFake()
	install(t, f, true, nil)
	clean := strings.Clone("clean-operand")
	hitClean := strings.Clone("clean-but-in-a-marked-granule")
	tainted := strings.Clone("tainted-operand")
	unknown := strings.Clone("contended-operand")
	f.markString(hitClean, ConfirmClean)
	f.markString(tainted, ConfirmTainted)
	f.markString(unknown, ConfirmUnknown)

	require.False(t, concatPre(nil))
	require.False(t, concatPre([]string{"", ""}))
	f.confirms.Store(0)
	if !FilterHit(&f.filter, stringPointer(clean)) {
		require.False(t, concatPre([]string{clean, clean}))
		require.Zero(t, f.confirms.Load(), "a filter miss does not call confirm")
	}
	require.False(t, concatPre([]string{hitClean}), "a clean filter hit")
	require.True(t, concatPre([]string{hitClean, tainted}), "an operand after the first hit")
	require.True(t, concatPre([]string{tainted, hitClean}))
	require.True(t, concatPre([]string{unknown}), "contention forces the heap")
}

func TestPreRecoversPanic(t *testing.T) {
	f := newFake()
	install(t, f, true, nil)
	value := strings.Clone("panic-operand")
	f.markString(value, ConfirmClean)
	f.panics = true
	before := Snapshot().HookPanics
	require.True(t, concatPre([]string{value}), "a panic forces the heap")
	require.True(t, strPre(value))
	require.Equal(t, before+2, Snapshot().HookPanics)
	f.panics = false
	require.False(t, concatPre([]string{value}), "the next call runs normally")
}

func TestConversionPre(t *testing.T) {
	require.False(t, bytesPre(nil, 0), "no binding")
	f := newFake()
	install(t, f, false, nil)
	tainted := strings.Clone("tainted-input")
	f.markString(tainted, ConfirmTainted)
	data := unsafe.StringData(tainted)
	require.False(t, bytesPre(nil, 4))
	require.False(t, bytesPre(data, 0))
	require.True(t, bytesPre(data, len(tainted)))
	require.False(t, strPre(tainted), "the string-to-slice switch is off")
	atomic.StoreUint32(&s2sGate, 1)
	f.confirms.Store(0)
	require.True(t, strPre(tainted))
	require.Equal(t, int32(1), f.confirms.Load())
	require.False(t, strPre(""))

	runes := []rune("runes")
	f.mark(uintptr(unsafe.Pointer(&runes[0])))
	f.tainted[uintptr(unsafe.Pointer(&runes[0]))] = ConfirmTainted
	require.True(t, runesPre(runes))
	require.False(t, runesPre(nil))
}

type recorder struct {
	concat, concatBytes, fromBytes, toBytes, fromRunes, toRunes int
	panics                                                      bool
}

func (r *recorder) callbacks() *Callbacks {
	check := func() {
		if r.panics {
			panic("callback failure")
		}
	}
	return &Callbacks{
		Concat:      func(string, []string) { r.concat++; check() },
		ConcatBytes: func([]byte, []string) { r.concatBytes++; check() },
		FromBytes:   func(string, []byte) { r.fromBytes++; check() },
		ToBytes:     func([]byte, string) { r.toBytes++; check() },
		FromRunes:   func(string, []rune) { r.fromRunes++; check() },
		ToRunes:     func([]rune, string) { r.toRunes++; check() },
	}
}

func (r *recorder) total() int {
	return r.concat + r.concatBytes + r.fromBytes + r.toBytes + r.fromRunes + r.toRunes
}

func callAllHooks(input string, runes []rune) {
	result := strings.Clone("result-value")
	bytesResult := []byte("result-value")
	runesResult := []rune("result-value")
	concatHook(result, []string{"x", input})
	concatBytesHook(bytesResult, []string{input, "x"})
	fromBytesHook(result, unsafe.StringData(input), len(input))
	toBytesHook(bytesResult, input)
	fromRunesHook(result, runes)
	toRunesHook(runesResult, input)
}

func TestResultHooksCallCallbacksOnlyOnFilterHit(t *testing.T) {
	var r recorder
	f := newFake()
	install(t, f, true, r.callbacks())
	input := strings.Clone("hook-input")
	runes := []rune("hook-runes")
	if !FilterHit(&f.filter, stringPointer(input)) && !FilterHit(&f.filter, uintptr(unsafe.Pointer(&runes[0]))) {
		callAllHooks(input, runes)
		require.Zero(t, r.total(), "a filter miss calls no callback")
	}

	f.mark(stringPointer(input))
	f.mark(uintptr(unsafe.Pointer(&runes[0])))
	callAllHooks(input, runes)
	require.Equal(t, recorder{1, 1, 1, 1, 1, 1, false}, r)

	// Results shorter than 2 bytes cannot be roots. An empty []rune result
	// is not a result.
	concatHook("x", []string{input})
	concatBytesHook([]byte("x"), []string{input})
	fromBytesHook("x", unsafe.StringData(input), 1)
	toRunesHook(nil, input)
	fromRunesHook("", runes)
	require.Equal(t, 6, r.total())

	atomic.StoreUint32(&s2sGate, 0)
	callAllHooks(input, runes)
	require.Equal(t, 1, r.toBytes, "the switch is off")
	require.Equal(t, 1, r.toRunes, "the switch is off")
	require.Equal(t, 2, r.concat)
}

func TestResultHooksWithoutCallbacks(t *testing.T) {
	f := newFake()
	install(t, f, true, &Callbacks{})
	input := strings.Clone("hook-input")
	runes := []rune("hook-runes")
	f.mark(stringPointer(input))
	f.mark(uintptr(unsafe.Pointer(&runes[0])))
	callAllHooks(input, runes) // must not panic
	callbacks.Store(nil)
	callAllHooks(input, runes)
	binding.Store(nil)
	var r recorder
	callbacks.Store(r.callbacks())
	callAllHooks(input, runes)
	require.Zero(t, r.total(), "no binding: no filter, no callback")
}

func TestCallbackPanicIsRecovered(t *testing.T) {
	r := recorder{panics: true}
	f := newFake()
	install(t, f, true, r.callbacks())
	input := strings.Clone("hook-input")
	runes := []rune("hook-runes")
	f.mark(stringPointer(input))
	f.mark(uintptr(unsafe.Pointer(&runes[0])))
	before := Snapshot().HookPanics
	callAllHooks(input, runes)
	require.Equal(t, before+6, Snapshot().HookPanics)
	r.panics = false
	callAllHooks(input, runes)
	require.Equal(t, 12, r.total(), "the next calls run normally")
	require.Equal(t, before+6, Snapshot().HookPanics)
}

func TestCountEntries(t *testing.T) {
	install(t, newFake(), true, nil)
	previous := CountEntries(false)
	t.Cleanup(func() { CountEntries(previous) })
	before := Snapshot().HookEntries
	concatPre([]string{"a"})
	require.Equal(t, before, Snapshot().HookEntries)
	CountEntries(true)
	input := strings.Clone("count")
	runes := []rune("count")
	concatPre([]string{input})
	bytesPre(unsafe.StringData(input), len(input))
	strPre(input)
	runesPre(runes)
	callAllHooks(input, runes)
	require.Equal(t, before+10, Snapshot().HookEntries, "each of the 10 bridge functions counts one entry")
}

func TestCleanPathsDoNotAllocate(t *testing.T) {
	var r recorder
	f := newFake()
	install(t, f, true, r.callbacks())
	clean := strings.Clone("clean-operand-value")
	hitClean := strings.Clone("clean-but-in-a-marked-granule")
	f.markString(hitClean, ConfirmClean)
	operands := []string{clean, hitClean, clean}
	result := strings.Clone("result-value")
	bytesResult := []byte("result-value")
	runes := []rune("clean-runes")
	runesResult := []rune("result-value")
	// The operand slices exist before the measured calls. In the runtime the
	// //go:noescape declarations keep them on the stack; a direct call from
	// this package cannot use those declarations.
	single := []string{clean}
	allocs := testing.AllocsPerRun(1000, func() {
		concatPre(operands)
		bytesPre(unsafe.StringData(hitClean), len(hitClean))
		strPre(hitClean)
		runesPre(runes)
		concatHook(result, single)
		concatBytesHook(bytesResult, single)
		fromBytesHook(result, unsafe.StringData(clean), len(clean))
		toBytesHook(bytesResult, clean)
		fromRunesHook(result, runes)
		toRunesHook(runesResult, clean)
	})
	require.Zero(t, allocs)

	// No binding: all 10 functions return at once, also for inputs that are
	// filter hits. First make sure that the inputs are filter hits.
	f.mark(uintptr(unsafe.Pointer(&runes[0])))
	callAll := func() {
		concatPre(operands)
		bytesPre(unsafe.StringData(hitClean), len(hitClean))
		strPre(hitClean)
		runesPre(runes)
		concatHook(result, operands)
		concatBytesHook(bytesResult, operands)
		fromBytesHook(result, unsafe.StringData(hitClean), len(hitClean))
		toBytesHook(bytesResult, hitClean)
		fromRunesHook(result, runes)
		toRunesHook(runesResult, hitClean)
	}
	r = recorder{}
	callAll()
	require.Equal(t, 6, r.total(), "with a binding, each input is a filter hit")
	r = recorder{}
	binding.Store(nil)
	require.Zero(t, testing.AllocsPerRun(1000, callAll), "no binding")
	require.Zero(t, r.total(), "no binding: no callback")
}

func TestFilterHitUsesBothTiers(t *testing.T) {
	var f Filter
	p := uintptr(0x1234_5678_0040)
	require.False(t, FilterHit(&f, p))
	f[bucketS(p)].Add(1)
	require.True(t, FilterHit(&f, p))
	require.True(t, FilterHit(&f, p+63-(p&63)), "the same tier S granule")
	f[bucketS(p)].Add(^uint32(0))
	f[bucketL(p)].Add(1)
	require.True(t, FilterHit(&f, p))
	require.True(t, FilterHit(&f, p&^4095+4095), "the same tier L granule")
	require.Equal(t, TierLBit|(p>>ShiftL+1), GranuleKey(p, true))
	require.Equal(t, p>>ShiftS+1, GranuleKey(p, false))

	// The written-out FilterHit is the same as the bucketS / bucketL form.
	for i := range uintptr(4096) {
		q := p + i*977
		var single Filter
		single[bucketS(q)].Add(1)
		require.True(t, FilterHit(&single, q))
		single[bucketS(q)].Add(^uint32(0))
		single[bucketL(q)].Add(1)
		require.True(t, FilterHit(&single, q))
		single[bucketL(q)].Add(^uint32(0))
		require.False(t, FilterHit(&single, q))
	}
}

func TestLength32(t *testing.T) {
	_, ok := length32(0)
	require.False(t, ok)
	n, ok := length32(7)
	require.True(t, ok)
	require.Equal(t, uint32(7), n)
	if unsafe.Sizeof(0) == 8 {
		tooLong := maxLength + 1
		_, ok = length32(int(tooLong))
		require.False(t, ok)
	}
}
