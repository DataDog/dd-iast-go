// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/propbridge"
	"github.com/stretchr/testify/require"
)

// describe returns the segments of r: "start-end=name:value" for an
// attributed segment, "start-end=foreign" for a foreign segment.
func describe(r *Attribution) string {
	parts := make([]string, 0, r.N)
	for i := 0; i < r.N; i++ {
		s := r.Segments[i]
		label := "foreign"
		if source, ok := r.Source(i); ok {
			label = source.Name + ":" + source.Value
			if source.Kind == SourceBody {
				label = "body"
			}
		}
		parts = append(parts, fmt.Sprintf("%d-%d=%s", s.Start, s.Start+s.Length, label))
	}
	return strings.Join(parts, " ")
}

func attributeBytes(t *testing.T, a Analysis, value []byte) string {
	t.Helper()
	var r Attribution
	a.AttributeBytes(value, &r)
	return describe(&r)
}

func newAnalysis(t *testing.T, m *Manager) Analysis {
	t.Helper()
	a, ok := m.Acquire(MaxAnalyses)
	require.True(t, ok)
	t.Cleanup(a.Finish)
	return a
}

func taintBytes(t *testing.T, a Analysis, name, value string) []byte {
	t.Helper()
	b, ok := a.TaintBytes(param, name, heapBytes(value))
	require.True(t, ok)
	return b
}

func setRangeLimit(t *testing.T, limit uint64) {
	t.Helper()
	previous := config.MaxRangeCount
	config.MaxRangeCount = limit
	t.Cleanup(func() { config.MaxRangeCount = previous })
}

func TestAttributeAddressLocateAndCheck(t *testing.T) {
	useFakeBits(t)
	setRangeLimit(t, 10)
	a := newAnalysis(t, NewManager())
	value := taintBytes(t, a, "q", "attacker")
	require.Equal(t, "0-8=q:attacker", attributeBytes(t, a, value))
	// A window has the same memory: the locator finds it.
	require.Equal(t, "0-4=q:attacker", attributeBytes(t, a, value[2:6]))

	// The application overwrites a part of the tainted buffer: the check
	// rejects the changed bytes (their bits stay: foreign).
	value[0] = '#'
	value[1] = '#'
	require.Equal(t, "0-2=foreign 2-8=q:attacker", attributeBytes(t, a, value))
}

func TestAttributeTwoRegistrationsAtOneAddress(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	a := newAnalysis(t, NewManager())
	buffer := heapBytes("first-value")
	_, ok := a.TaintBytes(param, "first", buffer)
	require.True(t, ok)
	// The buffer is reused for a second value at the same address.
	copy(buffer, "other-thing")
	f.clear(buffer)
	_, ok = a.TaintBytes(param, "second", buffer)
	require.True(t, ok)
	require.Equal(t, "0-11=second:other-thing", attributeBytes(t, a, buffer))
}

func TestAttributeAddressReuseWithOtherBytes(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	a := newAnalysis(t, NewManager())
	buffer := heapBytes("abcdef")
	_, ok := a.TaintBytes(param, "q", buffer)
	require.True(t, ok)
	// New bytes at the address of the source, with stale bits: no byte is
	// equal to the source, so all are foreign.
	copy(buffer, "XYZXYZ")
	require.True(t, f.any(uintptr(unsafe.Pointer(&buffer[0])), 6))
	require.Equal(t, "0-6=foreign", attributeBytes(t, a, buffer))
	var r Attribution
	require.False(t, a.AttributeBytes(buffer, &r), "a value with only foreign bytes is not reported")
}

func TestAttributeContentMatchOfCopy(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	a := newAnalysis(t, NewManager())
	value := taintBytes(t, a, "q", "attacker")
	clean := heapBytes("SELECT ")
	query := f.concat(clean, value, heapBytes(" x"))
	require.Equal(t, "7-15=q:attacker", attributeBytes(t, a, query))
}

func TestAttributeOneByteWindowConcat(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	a := newAnalysis(t, NewManager())
	value := taintBytes(t, a, "q", "xyz")
	query := f.concat(heapBytes("id="), value[1:2], heapBytes(";"))
	require.Equal(t, "3-4=q:xyz", attributeBytes(t, a, query))
}

func TestAttributeSegmentsOfOneRunWithTwoSources(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	a := newAnalysis(t, NewManager())
	left := taintBytes(t, a, "a", "left")
	right := taintBytes(t, a, "b", "RIGHT")
	joined := f.concat(left, right)
	require.Equal(t, "0-4=a:left 4-9=b:RIGHT", attributeBytes(t, a, joined))
}

func TestAttributeTieRule(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	a := newAnalysis(t, NewManager())
	taintBytes(t, a, "long", "abcdef")
	taintBytes(t, a, "short", "abc")
	// Content match: equal length, the shortest candidate wins.
	sink := f.concat(heapBytes("abc"))
	f.set(uintptr(unsafe.Pointer(&sink[0])), 3)
	require.Equal(t, "0-3=short:abc", attributeBytes(t, a, sink))

	// Equal length and equal size: the last registered candidate wins.
	b := newAnalysis(t, NewManager())
	taintBytes(t, b, "one", "same")
	taintBytes(t, b, "two", "same")
	sink = heapBytes("same")
	f.set(uintptr(unsafe.Pointer(&sink[0])), 4)
	require.Equal(t, "0-4=two:same", attributeBytes(t, b, sink))

	// The longest match wins over the shortest candidate.
	sink = heapBytes("abcde")
	f.set(uintptr(unsafe.Pointer(&sink[0])), 5)
	require.Equal(t, "0-5=long:abcdef", attributeBytes(t, a, sink))
}

func TestAttributeAddressWinsOverContent(t *testing.T) {
	useFakeBits(t)
	setRangeLimit(t, 10)
	a := newAnalysis(t, NewManager())
	first := taintBytes(t, a, "first", "token")
	taintBytes(t, a, "second", "token")
	// The content of both is equal; the address of first wins.
	require.Equal(t, "0-5=first:token", attributeBytes(t, a, first))
}

func TestAttributeOverflowIsForeign(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 2)
	a := newAnalysis(t, NewManager())
	one := taintBytes(t, a, "a", "aa")
	two := taintBytes(t, a, "b", "bb")
	three := taintBytes(t, a, "c", "cc")
	joined := f.concat(one, heapBytes("-"), two, heapBytes("-"), three, heapBytes("-"), one)
	var r Attribution
	require.True(t, a.AttributeBytes(joined, &r))
	require.True(t, r.Stopped())
	require.Equal(t, "0-2=a:aa 3-5=b:bb 6-8=foreign 9-11=foreign", describe(&r))
}

func TestAttributeForeignBytesOfOtherOwner(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	alpha := newAnalysis(t, m)
	bravo := newAnalysis(t, m)
	a := taintBytes(t, alpha, "id", "alpha")
	b := taintBytes(t, bravo, "id", "XYZ")
	shared := f.concat(a, heapBytes("|"), b)
	require.Equal(t, "0-5=id:alpha 6-9=foreign", attributeBytes(t, alpha, shared))
	require.Equal(t, "0-5=foreign 6-9=id:XYZ", attributeBytes(t, bravo, shared))
	var r Attribution
	require.False(t, alpha.AttributeBytes(shared[6:], &r), "only bytes of bravo: no report for alpha")
}

func TestAttributeOwnerlessSink(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	alpha := newAnalysis(t, m)
	bravo := newAnalysis(t, m)
	taintBytes(t, alpha, "a", "alpha")
	b := taintBytes(t, bravo, "b", "XYZ")
	var r Attribution
	// The address locator of bravo matches.
	require.True(t, m.AttributeBytesAny(b, Owner{}, &r))
	bravoOwner, _ := bravo.Owner()
	require.Equal(t, bravoOwner, r.Owner)
	// A copy: content match.
	sink := f.concat(heapBytes("ls "), b)
	require.True(t, m.AttributeBytesAny(sink, Owner{}, &r))
	require.Equal(t, bravoOwner, r.Owner)
	require.Equal(t, "3-6=b:XYZ", describe(&r))
	// A preferred owner without a match is skipped.
	alphaOwner, _ := alpha.Owner()
	require.True(t, m.AttributeBytesAny(sink, alphaOwner, &r))
	require.Equal(t, bravoOwner, r.Owner)
	// No owner: no report.
	clean := heapBytes("clean")
	require.False(t, m.AttributeBytesAny(clean, Owner{}, &r))
}

func TestAttributeUseAfterFinish(t *testing.T) {
	useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	a, ok := m.Acquire(1)
	require.True(t, ok)
	value := taintBytes(t, a, "q", "attacker")
	a.Finish()
	var r Attribution
	require.False(t, a.AttributeBytes(value, &r))
	require.False(t, m.AttributeBytesAny(value, Owner{}, &r))
}

func TestDerivedPositionalTwoSourcesAndTwoOwners(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	alpha := newAnalysis(t, m)
	bravo := newAnalysis(t, m)
	a := taintBytes(t, alpha, "a", "ab")
	c := taintBytes(t, alpha, "c", "cd")
	x := taintBytes(t, bravo, "x", "xy")
	input := f.concat(a, c, x)
	out := heapBytes(strings.ToUpper(string(input)))
	f.set(uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)))
	m.derived(unsafe.Pointer(&out[0]), uintptr(len(out)), unsafe.Pointer(&input[0]), uintptr(len(input)), propbridge.Positional)
	require.Equal(t, "0-2=a:ab 2-4=c:cd 4-6=foreign", attributeBytes(t, alpha, out))
	require.Equal(t, "0-4=foreign 4-6=x:xy", attributeBytes(t, bravo, out))
	// A copy of the derived value: content match on the derived copy.
	copied := f.concat(heapBytes("q="), out[1:5])
	require.Equal(t, "2-3=a:ab 3-5=c:cd 5-6=foreign", attributeBytes(t, alpha, copied))
}

func TestDerivedCoarseFirstSourceOfOwner(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	alpha := newAnalysis(t, m)
	first := taintBytes(t, alpha, "first", "ab")
	second := taintBytes(t, alpha, "second", "cd")
	input := f.concat(heapBytes("<"), first, second)
	out := heapBytes("&lt;abcd")
	f.set(uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)))
	m.derived(unsafe.Pointer(&out[0]), uintptr(len(out)), unsafe.Pointer(&input[0]), uintptr(len(input)), propbridge.Coarse)
	require.Equal(t, "0-8=first:ab", attributeBytes(t, alpha, out))
	// A second call for the same output (another input) does not add a
	// second entry for the owner.
	m.derived(unsafe.Pointer(&out[0]), uintptr(len(out)), unsafe.Pointer(&second[0]), uintptr(len(second)), propbridge.Coarse)
	m.use(alpha.slot, alpha.generation, alpha.id, func(d *ownerData) {
		require.Equal(t, 1, d.nderived)
	})
}

func TestDerivedTableFullDropsEntry(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	alpha := newAnalysis(t, m)
	input := taintBytes(t, alpha, "q", "ab")
	outputs := make([][]byte, MaxDerived+1)
	for i := range outputs {
		outputs[i] = heapBytes(fmt.Sprintf("<%02d>", i))
		if i == MaxDerived {
			outputs[i] = heapBytes("~~~~")
		}
		f.set(uintptr(unsafe.Pointer(&outputs[i][0])), 4)
		m.derived(unsafe.Pointer(&outputs[i][0]), 4, unsafe.Pointer(&input[0]), 2, propbridge.Coarse)
	}
	require.Equal(t, "0-4=q:ab", attributeBytes(t, alpha, outputs[0]))
	// The last entry is dropped: its bits stay, its bytes are foreign ("~"
	// is in no copy).
	last := outputs[MaxDerived]
	require.True(t, f.any(uintptr(unsafe.Pointer(&last[0])), 4))
	require.Equal(t, "0-4=foreign", attributeBytes(t, alpha, last))
}

func TestBudgetUsed(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	alpha := newAnalysis(t, m)

	// A short substring of a large allocation is charged by its length.
	large := heapString(strings.Repeat("x", 1<<20) + "needle")
	_, ok := alpha.TaintString(param, "n", large[1<<20:])
	require.True(t, ok)
	require.Equal(t, OwnerBudget-len("n")-len("needle"), alpha.Budget())

	// A source name of more than MaxNameBytes is refused.
	_, ok = alpha.TaintString(param, strings.Repeat("n", MaxNameBytes+1), heapString("value"))
	require.False(t, ok)
	_, ok = alpha.TaintString(param, strings.Repeat("n", MaxNameBytes), heapString("value"))
	require.True(t, ok)

	// Fill the budget with large sources.
	for i := 0; ; i++ {
		value := heapString(fmt.Sprintf("%05d", i) + strings.Repeat("v", MaxValueBytes-5))
		if _, ok := alpha.TaintString(param, "big", value); !ok {
			require.Less(t, alpha.Budget(), MaxValueBytes+3)
			break
		}
	}
	// A derived copy that does not fit is dropped: its bytes are foreign.
	before := alpha.Budget()
	input := taintBytesOrFail(t, alpha, "ab")
	out := heapBytes(strings.Repeat("#", before+1))
	f.set(uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)))
	m.derived(unsafe.Pointer(&out[0]), uintptr(len(out)), unsafe.Pointer(&input[0]), 2, propbridge.Coarse)
	var r Attribution
	require.False(t, alpha.AttributeBytes(out, &r))
}

func taintBytesOrFail(t *testing.T, a Analysis, value string) []byte {
	t.Helper()
	b, ok := a.TaintBytes(param, "", heapBytes(value))
	require.True(t, ok)
	return b
}

func TestSourceAdmissionAndClone(t *testing.T) {
	f := useFakeBits(t)
	m := NewManager()
	a := newAnalysis(t, m)
	_, ok := a.TaintString(param, "q", heapString("x"))
	require.False(t, ok, "a 1-byte value is not admitted")
	_, ok = a.TaintString(param, "q", heapString(strings.Repeat("x", MaxValueBytes+1)))
	require.False(t, ok, "a value longer than 64 KiB is not admitted")
	_, ok = a.TaintString(0, "q", heapString("value"))
	require.False(t, ok, "origin 0 is not valid")

	// In place when possible.
	value := heapString("in-place")
	tainted, ok := a.TaintString(param, "q", value)
	require.True(t, ok)
	require.Same(t, unsafe.StringData(value), unsafe.StringData(tainted))

	// A clone when the memory cannot be tainted.
	refused := heapString("refused")
	refusedAddr := uintptr(unsafe.Pointer(unsafe.StringData(refused)))
	f.refuse = func(p, _ uintptr) bool { return p == refusedAddr }
	clone, ok := a.TaintString(param, "r", refused)
	require.True(t, ok)
	require.NotSame(t, unsafe.StringData(refused), unsafe.StringData(clone))
	require.Equal(t, "refused", clone)
	require.False(t, a.TaintStringInPlace(param, "s", refused), "in place: no clone")

	bytesValue := make([]byte, 6, 12)
	escapeSink.Store(&bytesValue)
	copy(bytesValue, "attack")
	bytesAddr := uintptr(unsafe.Pointer(&bytesValue[0]))
	f.refuse = func(p, _ uintptr) bool { return p == bytesAddr }
	clonedBytes, ok := a.TaintBytes(param, "b", bytesValue)
	require.True(t, ok)
	require.Equal(t, len(bytesValue), len(clonedBytes))
	require.Equal(t, cap(bytesValue), cap(clonedBytes))
	require.NotSame(t, &bytesValue[0], &clonedBytes[0])
	f.refuse = nil

	// The source value is a copy: a change of the bytes does not change it.
	clonedBytes[0] = 'A'
	source, ok := a.Source(2)
	require.True(t, ok)
	require.Equal(t, "attack", source.Value)

	// Duplicates use the existing record.
	count := a.SourceCount()
	_, ok = a.TaintString(param, "q", heapString("in-place"))
	require.True(t, ok)
	require.Equal(t, count, a.SourceCount())
}

func TestIsSource(t *testing.T) {
	useFakeBits(t)
	a := newAnalysis(t, NewManager())
	value := heapString("source-value")
	tainted, ok := a.TaintString(param, "q", value)
	require.True(t, ok)
	require.True(t, a.IsSource(tainted))
	require.False(t, a.IsSource(tainted[1:]), "a window is not the source")
	require.False(t, a.IsSource(heapString("source-value")), "equal bytes at another address are not the source")
}

func TestRuneConversionsKeepTheSource(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	a := newAnalysis(t, m)
	source := taintBytes(t, a, "q", "\xff\xfe")
	input := f.concat(heapBytes("é"), source)
	// string -> []rune: 3 runes (é, U+FFFD, U+FFFD).
	runes := []rune(string(input))
	require.Len(t, runes, 3)
	runeBytes := unsafe.Slice((*byte)(unsafe.Pointer(&runes[0])), 12)
	f.set(uintptr(unsafe.Pointer(&runes[1])), 8)
	m.runes(unsafe.Pointer(&runes[0]), 12, unsafe.Pointer(&input[0]), uintptr(len(input)), propbridge.RunesFromString)
	require.Equal(t, "4-12=q:\xff\xfe", attributeBytes(t, a, runeBytes))

	// []rune -> string: "é" (2 bytes) + 2 x U+FFFD (3 bytes each).
	text := heapBytes(string(runes))
	require.Len(t, text, 8)
	f.set(uintptr(unsafe.Pointer(&text[2])), 6)
	m.runes(unsafe.Pointer(&text[0]), uintptr(len(text)), unsafe.Pointer(&runes[0]), 12, propbridge.StringFromRunes)
	require.Equal(t, "2-8=q:\xff\xfe", attributeBytes(t, a, text))

	// The sink gets a copy of the text: content match on the derived copy.
	sink := f.concat(heapBytes("x="), text[2:])
	require.Equal(t, "2-8=q:\xff\xfe", attributeBytes(t, a, sink))
}

func TestBodyRegistrationAndReads(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	a := newAnalysis(t, m)
	body := new([64]byte)
	other := new([64]byte)
	require.True(t, a.RegisterBody(unsafe.Pointer(body)))

	// A Read of another body object (a client response) is not tainted.
	chunk := heapBytes("not-a-request")
	m.bodyRead(unsafe.Pointer(other), unsafe.Pointer(&chunk[0]), uintptr(len(chunk)))
	require.False(t, f.any(uintptr(unsafe.Pointer(&chunk[0])), uintptr(len(chunk))))

	// 8 KiB of JSON in 4 KiB reads; the sink uses a field after byte 4096.
	document := strings.Repeat(" ", 4100) + `{"id":"evil"}` + strings.Repeat(" ", 8192-4100-13)
	buffer := heapBytes(strings.Repeat("\x00", 4096))
	for offset := 0; offset < len(document); offset += len(buffer) {
		n := copy(buffer, document[offset:])
		m.bodyRead(unsafe.Pointer(body), unsafe.Pointer(&buffer[0]), uintptr(n))
		require.True(t, f.any(uintptr(unsafe.Pointer(&buffer[0])), uintptr(n)))
	}
	// The field is a copy of the second chunk (the buffer was reused).
	field := f.concat(buffer[4100-4096+7 : 4100-4096+11])
	require.Equal(t, "evil", string(field))
	require.Equal(t, "0-4=body", attributeBytes(t, a, field))
	source, ok := a.Source(BodySourceID)
	require.True(t, ok)
	require.Equal(t, constants.OriginHttpRequestBody, source.Origin)
	require.Equal(t, document, source.Value)
	// The located chunk: the buffer itself (last read).
	require.Equal(t, "0-4096=body", attributeBytes(t, a, buffer))
}

func TestBodyAfterCopyLimitIsForeign(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	a := newAnalysis(t, m)
	body := new([64]byte)
	require.True(t, a.RegisterBody(unsafe.Pointer(body)))
	first := heapBytes(strings.Repeat("a", MaxBodyCopy))
	m.bodyRead(unsafe.Pointer(body), unsafe.Pointer(&first[0]), uintptr(len(first)))
	late := heapBytes("ZZZZ")
	m.bodyRead(unsafe.Pointer(body), unsafe.Pointer(&late[0]), uintptr(len(late)))
	require.True(t, f.any(uintptr(unsafe.Pointer(&late[0])), 4), "the bits stay")
	require.Equal(t, "0-4=foreign", attributeBytes(t, a, late))
}

func TestIsTaintedNeedsActiveOwner(t *testing.T) {
	useFakeBits(t)
	m := NewManager()
	previous := processManager.Swap(m)
	t.Cleanup(func() { processManager.Store(previous) })
	a, ok := m.Acquire(1)
	require.True(t, ok)
	value := taintBytesOrFail(t, a, "attacker")
	require.True(t, IsTaintedBytes(value))
	require.False(t, IsTaintedString(heapString("attacker")), "no bits: not tainted")
	a.Finish()
	require.False(t, IsTaintedBytes(value), "false after Finish")
}

// TestCloneCapacityBound: the clone of a refused byte-slice source keeps the
// capacity of the value; a capacity larger than MaxValueBytes is not cloned
// (it can be a very large allocation), and the taint is dropped.
func TestCloneCapacityBound(t *testing.T) {
	f := useFakeBits(t)
	a := newAnalysis(t, NewManager())
	f.refuse = func(uintptr, uintptr) bool { return true }
	t.Cleanup(func() { f.refuse = nil })

	large := make([]byte, 2, 512<<20)
	escapeSink.Store(&large)
	copy(large, "ab")
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	result, ok := a.TaintBytes(param, "q", large)
	runtime.ReadMemStats(&after)
	require.False(t, ok, "a capacity larger than MaxValueBytes drops the taint")
	require.Same(t, &large[0], &result[0])
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(MaxValueBytes), "no large clone")
	require.Zero(t, a.SourceCount())
	require.Equal(t, OwnerBudget, a.Budget(), "the budget is given back")

	// At the bound, the clone keeps the capacity.
	bound := make([]byte, 2, MaxValueBytes)
	escapeSink.Store(&bound)
	copy(bound, "cd")
	boundAddr := uintptr(unsafe.Pointer(&bound[0]))
	f.refuse = func(p, _ uintptr) bool { return p == boundAddr }
	clone, ok := a.TaintBytes(param, "q", bound)
	require.True(t, ok)
	require.NotSame(t, &bound[0], &clone[0])
	require.Equal(t, MaxValueBytes, cap(clone))
	require.Equal(t, 1, a.SourceCount())
}

// TestDerivedAgainFromOtherSource: when the same output (address and bytes)
// is derived again from a different source, the entry gets the new
// provenance.
func TestDerivedAgainFromOtherSource(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	m := NewManager()
	alpha := newAnalysis(t, m)
	first := taintBytes(t, alpha, "first", "payload")
	second := taintBytes(t, alpha, "second", "payload")
	out := heapBytes("PAYLOAD")
	f.set(uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)))
	m.derived(unsafe.Pointer(&out[0]), uintptr(len(out)), unsafe.Pointer(&first[0]), uintptr(len(first)), propbridge.Positional)
	require.Equal(t, "0-7=first:payload", attributeBytes(t, alpha, out))
	m.derived(unsafe.Pointer(&out[0]), uintptr(len(out)), unsafe.Pointer(&second[0]), uintptr(len(second)), propbridge.Positional)
	require.Equal(t, "0-7=second:payload", attributeBytes(t, alpha, out))
	m.use(alpha.slot, alpha.generation, alpha.id, func(d *ownerData) {
		require.Equal(t, 1, d.nderived, "no second entry")
	})
	// The order also moves: a content match of a copy finds the latest
	// derivation first.
	m.derived(unsafe.Pointer(&out[0]), uintptr(len(out)), unsafe.Pointer(&first[0]), uintptr(len(first)), propbridge.Positional)
	copied := f.concat(heapBytes("x"), out)
	require.Equal(t, "1-8=first:payload", attributeBytes(t, alpha, copied))
}

// describeNames is describe with the source names only (the values of
// these tests are large).
func describeNames(r *Attribution) string {
	parts := make([]string, 0, r.N)
	for i := 0; i < r.N; i++ {
		s := r.Segments[i]
		label := "foreign"
		if source, ok := r.Source(i); ok {
			label = source.Name
		}
		parts = append(parts, fmt.Sprintf("%d-%d=%s", s.Start, s.Start+s.Length, label))
	}
	return strings.Join(parts, " ")
}

// taintRuns returns a heap copy of value, with bits on the bytes where mask
// is 't'.
func taintRuns(f *fakeBits, value, mask string) []byte {
	b := heapBytes(value)
	for i := range mask {
		if mask[i] == 't' {
			f.set(uintptr(unsafe.Pointer(&b[i])), 1)
		}
	}
	return b
}

// TestCheckBudgetExhausted: the 4096 candidate checks stop the attribution
// in a run; the remaining bytes of the run and the next runs are foreign.
func TestCheckBudgetExhausted(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	a := newAnalysis(t, NewManager())
	// 5000 occurrences of 'a': a content match of "ab" checks each of them.
	taintBytes(t, a, "s", strings.Repeat("a", 5000))
	taintBytes(t, a, "z", "zz")
	// Run 1 ("a", 1 check), run 2 ("ab": the checks stop), run 3.
	value := taintRuns(f, "a-ab-ab", "t-tt-tt")
	var r Attribution
	// The 1-byte match is weak: the segments stay, but the value is not
	// tainted for the owner.
	require.False(t, a.AttributeBytes(value, &r))
	require.True(t, r.Stopped())
	require.Equal(t, "0-1=s 2-4=foreign 5-7=foreign", describeNames(&r))

	// In one run: "zz" matches with 1 check, then "ab" uses all the checks;
	// the remaining bytes of the run are foreign.
	value = taintRuns(f, "zzab", "tttt")
	require.True(t, a.AttributeBytes(value, &r), "zz is a full copy of a 2-byte source: strong")
	require.True(t, r.Stopped())
	require.Equal(t, "0-2=z 2-4=foreign", describeNames(&r))
}

// TestCompareBudgetExhausted: the 1 MiB compare budget stops the
// attribution; the remaining tainted bytes are foreign.
func TestCompareBudgetExhausted(t *testing.T) {
	f := useFakeBits(t)
	setRangeLimit(t, 10)
	a := newAnalysis(t, NewManager())
	// 3 sources of 64 KiB, with 'a' only at the end: a content match of "a"
	// scans all of them (3 x 65537 bytes, 3 checks). The byte set of the
	// copies takes 3 x 65536 bytes. Thus 4 matches fit in 1 MiB, not 5.
	for _, name := range []string{"s1", "s2", "s3"} {
		taintBytes(t, a, name, strings.Repeat("x", MaxValueBytes-1)+"a")
	}
	value := taintRuns(f, "a-a-a-a-a-a", "t-t-t-t-t-t")
	var r Attribution
	// 1-byte matches only (weak): the segments stay, not tainted.
	require.False(t, a.AttributeBytes(value, &r))
	require.True(t, r.Stopped())
	// Equal matches: the last registered source wins.
	require.Equal(t, "0-1=s3 2-3=s3 4-5=s3 6-7=s3 8-9=foreign 10-11=foreign", describeNames(&r))

	// In one run (the adjacent segments of one source merge).
	value = taintRuns(f, "aaaaaa", "tttttt")
	require.False(t, a.AttributeBytes(value, &r))
	require.True(t, r.Stopped())
	require.Equal(t, "0-4=s3 4-6=foreign", describeNames(&r))
}
