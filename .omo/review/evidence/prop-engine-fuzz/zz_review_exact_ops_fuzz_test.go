// Review harness (prop-engine-fuzz): differential fuzzer that applies random
// stdlib string/byte operations through the engine's exact entry points and
// checks every produced value against a per-byte, per-owner provenance oracle.

package propagation_test

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

const (
	xoSteps     = 14
	xoMaxOutput = 4 << 10
	xoOps       = 18
	xoWindows   = 32 // propagation.maxWindows
	xoMatches   = 32 // propagation.maxReplaceMatches
	xoInputs    = 16 // propagation.maxInputs
)

type xoCells = [sequenceOwnerCount][]sequenceCell

func FuzzExactStringOps(f *testing.F) {
	f.Add([]byte("ascii-repeated-values,a b,c"))
	f.Add([]byte("unicode-\u00e9-\u03bb-\u4e16\u754c"))
	f.Add([]byte{0xff, 0xfe, 'a', 0x80, 'a', 0xc3, 0xa9, ',', ' '})
	f.Add([]byte{})
	for op := range xoOps {
		f.Add([]byte{byte(op), byte(op * 7), byte(op * 13), 0x80, 'a', ',', 0xc3, 0xa9, byte(op), 3, 17, 200, 1})
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > sequenceMaxInput {
			encoded = encoded[:sequenceMaxInput]
		}
		taintStore, _ := beginScope(t)
		runExactOps(t, taintStore, encoded)
	})
}

func runExactOps(tb testing.TB, taintStore *store.Store, encoded []byte) {
	tb.Helper()
	cursor := newSequenceCursor(encoded)
	owners := [sequenceOwnerCount]*store.Owner{taintStore.Acquire(), taintStore.Acquire()}
	for index, owner := range owners {
		if owner.Disabled() {
			tb.Fatalf("owner %d admission unexpectedly failed", index)
		}
	}
	defer owners[1].Finish()
	defer owners[0].Finish()

	values := sequenceInitialValues(tb, owners, cursor)
	values = append(values, xoSeparatorValues(tb, owners, cursor)...)
	for index := range values {
		values[index] = xoAssert(tb, taintStore, owners, values[index], "initial value", false)
	}
	for step := range xoSteps {
		op := cursor.indexOf(xoOps)
		before := xoDrops(owners)
		results, keep, desc := xoApply(tb, cursor, values, op)
		allowMissing := xoDrops(owners) != before
		for index := range results {
			stage := fmt.Sprintf("step %d op %d %s result %d", step, op, desc, index)
			results[index] = xoAssert(tb, taintStore, owners, results[index], stage, allowMissing)
		}
		for _, index := range keep {
			if results[index].length() <= xoMaxOutput {
				values = append(values, results[index])
			}
		}
	}
}

func xoDrops(owners [sequenceOwnerCount]*store.Owner) uint64 {
	var total uint64
	for _, owner := range owners {
		c := owner.Counters()
		total += c.Full + c.Bytes + c.Ranges + c.Contention + c.Late + c.Stale + c.Fanout
	}
	return total
}

func xoSeparatorValues(tb testing.TB, owners [sequenceOwnerCount]*store.Owner, cursor *sequenceCursor) []sequenceValue {
	tb.Helper()
	const alphabet = ", a\t\u00e9b"
	var out []sequenceValue
	for _, kind := range []sequenceKind{sequenceString, sequenceBytes} {
		raw := make([]byte, 2+cursor.indexOf(5))
		for index := range raw {
			raw[index] = alphabet[cursor.indexOf(len(alphabet))]
		}
		var cells xoCells
		for ownerIndex := range cells {
			cells[ownerIndex] = make([]sequenceCell, len(raw))
			for position := range raw {
				selector := cursor.next()
				if selector%3 == 0 {
					continue
				}
				cells[ownerIndex][position] = sequenceCell{
					tainted: true,
					source:  ranges.SourceID(8 + (int(selector)+ownerIndex)%4),
					marks:   []uint64{0xe, 0xc, 0xa, 0x6}[int(selector)%4],
				}
			}
			cells[ownerIndex] = normalizeSequenceCells(cells[ownerIndex])
		}
		out = append(out, adoptSequenceValue(tb, owners, kind, raw, cells))
	}
	return out
}

// xoAssert checks the store contents for value against the oracle. When
// allowMissing is set (a bounded-drop counter moved during the operation), a
// missing owner contribution is accepted and the oracle is corrected to clean,
// but wrong ranges are never accepted.
func xoAssert(
	tb testing.TB,
	taintStore *store.Store,
	owners [sequenceOwnerCount]*store.Owner,
	value sequenceValue,
	stage string,
	allowMissing bool,
) sequenceValue {
	tb.Helper()
	for ownerIndex := range value.cells {
		if len(value.cells[ownerIndex]) != value.length() {
			tb.Fatalf("%s: oracle length mismatch owner %d: %d vs %d", stage, ownerIndex, len(value.cells[ownerIndex]), value.length())
		}
	}
	var key store.Key
	var valid bool
	if value.kind == sequenceString {
		key, valid = store.StringKey(value.text)
	} else {
		key, valid = store.BytesKey(value.data)
	}
	if !valid {
		for ownerIndex := range owners {
			if len(sequenceRanges(value.cells[ownerIndex])) != 0 {
				tb.Fatalf("%s: attributed bytes without a valid store key", stage)
			}
		}
		return value
	}
	var snapshot store.Snapshot
	if !taintStore.Lookup(key, &snapshot) {
		tb.Fatalf("%s: lookup unexpectedly contended", stage)
	}
	seen := [sequenceOwnerCount]bool{}
	for entryIndex := 0; entryIndex < snapshot.Len(); entryIndex++ {
		entry, ok := snapshot.At(entryIndex)
		if !ok {
			tb.Fatalf("%s: snapshot entry %d unavailable", stage, entryIndex)
		}
		if entry.Ranges.Len() == 0 {
			continue
		}
		ownerIndex := sequenceOwnerIndex(owners, entry)
		if ownerIndex < 0 {
			tb.Fatalf("%s: unexpected owner index=%d gen=%d id=%d", stage, entry.OwnerIndex, entry.OwnerGen, entry.OwnerID)
		}
		if seen[ownerIndex] {
			tb.Fatalf("%s: duplicate contribution for owner %d", stage, ownerIndex)
		}
		seen[ownerIndex] = true
		actual := make([]ranges.Range, entry.Ranges.Len())
		entry.Ranges.CopyTo(actual)
		// Range bound check first: never exceed the visible value length.
		for _, r := range actual {
			if r.Length == 0 || uint64(r.Start)+uint64(r.Length) > uint64(value.length()) {
				tb.Fatalf("%s: owner %d range %v exceeds value length %d (value=%q)", stage, ownerIndex, r, value.length(), value.valueBytes())
			}
		}
		expected := sequenceRanges(value.cells[ownerIndex])
		if !slices.Equal(expected, actual) {
			tb.Fatalf("%s: owner %d ranges differ (value=%q len=%d)\nexpected=%v\nactual=%v", stage, ownerIndex, value.valueBytes(), value.length(), expected, actual)
		}
	}
	for ownerIndex := range owners {
		if seen[ownerIndex] || len(sequenceRanges(value.cells[ownerIndex])) == 0 {
			continue
		}
		if !allowMissing {
			tb.Fatalf("%s: missing owner %d contribution (value=%q): expected %v", stage, ownerIndex, value.valueBytes(), sequenceRanges(value.cells[ownerIndex]))
		}
		value.cells[ownerIndex] = make([]sequenceCell, value.length())
	}
	return value
}

// ---- oracle helpers ----

func xoPick(cursor *sequenceCursor, values []sequenceValue, kind sequenceKind) sequenceValue {
	var candidates []int
	for index := range values {
		if values[index].kind == kind {
			candidates = append(candidates, index)
		}
	}
	return values[candidates[cursor.indexOf(len(candidates))]]
}

func xoClean(length int) xoCells {
	var cells xoCells
	for ownerIndex := range cells {
		cells[ownerIndex] = make([]sequenceCell, length)
	}
	return cells
}

func xoSlice(cells xoCells, low, high int) xoCells {
	var out xoCells
	for ownerIndex := range out {
		out[ownerIndex] = append([]sequenceCell(nil), cells[ownerIndex][low:high]...)
	}
	return out
}

func xoConcat(parts ...xoCells) xoCells {
	var out xoCells
	for ownerIndex := range out {
		out[ownerIndex] = []sequenceCell{}
		for _, part := range parts {
			out[ownerIndex] = append(out[ownerIndex], part[ownerIndex]...)
		}
	}
	return out
}

// xoCoarse models ranges.Coarse over parts: first contributing range source,
// marks intersected across every contributing range, whole output.
func xoCoarse(length int, parts ...xoCells) xoCells {
	out := xoClean(length)
	for ownerIndex := range out {
		found := false
		var source ranges.SourceID
		var marks uint64
		for _, part := range parts {
			for _, r := range sequenceRanges(part[ownerIndex]) {
				if !found {
					source, marks, found = r.SourceID, r.Marks, true
				} else {
					marks &= r.Marks
				}
			}
		}
		if found {
			for position := range out[ownerIndex] {
				out[ownerIndex][position] = sequenceCell{tainted: true, source: source, marks: marks}
			}
		}
	}
	return out
}

func xoStrOffset(input, output string) (int, bool) {
	if len(input) == 0 || len(output) == 0 {
		return 0, false
	}
	base := uintptr(unsafe.Pointer(unsafe.StringData(input)))
	ptr := uintptr(unsafe.Pointer(unsafe.StringData(output)))
	if ptr < base || ptr+uintptr(len(output)) > base+uintptr(len(input)) {
		return 0, false
	}
	return int(ptr - base), true
}

func xoBytesOffset(input, output []byte) (int, bool) {
	if len(input) == 0 || len(output) == 0 {
		return 0, false
	}
	base := uintptr(unsafe.Pointer(unsafe.SliceData(input)))
	ptr := uintptr(unsafe.Pointer(unsafe.SliceData(output)))
	if ptr < base || ptr+uintptr(len(output)) > base+uintptr(len(input)) {
		return 0, false
	}
	return int(ptr - base), true
}

func xoString(text string, cells xoCells, alias bool, op string) sequenceValue {
	v := sequenceValue{kind: sequenceString, text: text, cells: cells, operation: op}
	if alias {
		v.normalizeAlias()
	} else {
		v.normalizeFresh()
	}
	return v
}

func xoBytes(data []byte, cells xoCells, alias bool, op string) sequenceValue {
	v := sequenceValue{kind: sequenceBytes, data: data, cells: cells, operation: op}
	if alias {
		v.normalizeAlias()
	} else {
		v.normalizeFresh()
	}
	return v
}

// xoAppendCells appends parts to dst per owner in linear time.
func xoAppendCells(dst *xoCells, parts ...xoCells) {
	for ownerIndex := range dst {
		for _, part := range parts {
			dst[ownerIndex] = append(dst[ownerIndex], part[ownerIndex]...)
		}
	}
}

func xoWindowCells(cells xoCells, low, high int) xoCells {
	var out xoCells
	for ownerIndex := range out {
		out[ownerIndex] = cells[ownerIndex][low:high]
	}
	return out
}

// xoReplaceLen returns the effective match count and output length of
// strings.Replace / bytes.Replace without building the output.
func xoReplaceLen(input, old, repl []byte, n int) (int, int) {
	m := 0
	if n != 0 {
		m = bytes.Count(input, old)
	}
	if m == 0 {
		return 0, len(input)
	}
	if n < 0 || m < n {
		n = m
	}
	return n, len(input) + n*(len(repl)-len(old))
}

// xoReplaceCells mirrors strings.Replace / bytes.Replace byte for byte.
func xoReplaceCells(input []byte, inCells xoCells, old, repl []byte, replCells xoCells, n int) ([]byte, xoCells, int) {
	m := 0
	if n != 0 {
		m = bytes.Count(input, old)
	}
	if m == 0 {
		return append([]byte(nil), input...), xoSlice(inCells, 0, len(input)), 0
	}
	if n < 0 || m < n {
		n = m
	}
	var out []byte
	cells := xoConcat()
	start := 0
	for i := 0; i < n; i++ {
		j := start
		if len(old) == 0 {
			if i > 0 {
				_, width := utf8.DecodeRune(input[start:])
				j += width
			}
		} else {
			j += bytes.Index(input[start:], old)
		}
		out = append(out, input[start:j]...)
		out = append(out, repl...)
		xoAppendCells(&cells, xoWindowCells(inCells, start, j), replCells)
		start = j + len(old)
	}
	out = append(out, input[start:]...)
	xoAppendCells(&cells, xoWindowCells(inCells, start, len(input)))
	return out, cells, n
}

// xoValidUTF8Runs counts invalid runs as bytes.ToValidUTF8 does.
func xoValidUTF8Runs(input []byte) int {
	runs := 0
	invalid := false
	for i := 0; i < len(input); {
		if input[i] < utf8.RuneSelf {
			i++
			invalid = false
			continue
		}
		_, width := utf8.DecodeRune(input[i:])
		if width == 1 {
			i++
			if !invalid {
				invalid = true
				runs++
			}
			continue
		}
		invalid = false
		i += width
	}
	return runs
}

// xoValidUTF8Cells mirrors bytes.ToValidUTF8.
func xoValidUTF8Cells(input []byte, inCells xoCells, repl []byte, replCells xoCells) ([]byte, xoCells, int) {
	var out []byte
	cells := xoConcat()
	runs := 0
	invalid := false
	for i := 0; i < len(input); {
		c := input[i]
		if c < utf8.RuneSelf {
			out = append(out, c)
			xoAppendCells(&cells, xoWindowCells(inCells, i, i+1))
			i++
			invalid = false
			continue
		}
		_, width := utf8.DecodeRune(input[i:])
		if width == 1 {
			i++
			if !invalid {
				invalid = true
				runs++
				out = append(out, repl...)
				xoAppendCells(&cells, replCells)
			}
			continue
		}
		invalid = false
		out = append(out, input[i:i+width]...)
		xoAppendCells(&cells, xoWindowCells(inCells, i, i+width))
		i += width
	}
	return out, cells, runs
}

func xoASCII(b []byte) bool {
	for _, c := range b {
		if c >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func xoSubstring(cursor *sequenceCursor, value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	start := cursor.indexOf(len(value))
	length := 1 + cursor.indexOf(min(3, len(value)-start))
	return append([]byte(nil), value[start:start+length]...)
}

// ---- operations ----

func xoApply(tb testing.TB, cursor *sequenceCursor, values []sequenceValue, op int) ([]sequenceValue, []int, string) {
	tb.Helper()
	switch op {
	case 0:
		return xoJoinString(tb, cursor, values)
	case 1:
		return xoReplaceString(tb, cursor, values)
	case 2:
		return xoRepeatString(tb, cursor, values)
	case 3:
		return xoStringWindows(tb, cursor, values)
	case 4:
		return xoStringWindow(tb, cursor, values)
	case 5:
		return xoCaseString(tb, cursor, values)
	case 6:
		return xoCopyString(tb, cursor, values)
	case 7:
		return xoCoarseString(tb, cursor, values)
	case 8:
		return xoBytesToString(tb, cursor, values)
	case 9:
		return xoJoinBytes(tb, cursor, values)
	case 10:
		return xoReplaceBytes(tb, cursor, values)
	case 11:
		return xoRepeatBytes(tb, cursor, values)
	case 12:
		return xoByteWindows(tb, cursor, values)
	case 13:
		return xoByteWindow(tb, cursor, values)
	case 14:
		return xoCaseBytes(tb, cursor, values)
	case 15:
		return xoCopyBytes(tb, cursor, values)
	case 16:
		return xoValidUTF8(tb, cursor, values)
	default:
		return xoMapBytes(tb, cursor, values)
	}
}

func one(v sequenceValue) ([]sequenceValue, []int, string) {
	return []sequenceValue{v}, []int{0}, v.operation
}

func xoJoinString(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	n := 1 + cursor.indexOf(20)
	elements := make([]string, 0, n)
	cells := make([]xoCells, 0, n)
	total := 0
	for range n {
		var v sequenceValue
		switch cursor.indexOf(6) {
		case 0:
			v = sequenceValue{kind: sequenceString, text: "", cells: xoClean(0)}
		case 1:
			v = sequenceValue{kind: sequenceString, text: "ab", cells: xoClean(2)}
		default:
			v = xoPick(cursor, values, sequenceString)
		}
		if total+len(v.text) > xoMaxOutput/2 {
			break
		}
		total += len(v.text)
		elements = append(elements, v.text)
		cells = append(cells, v.cells)
	}
	var sep sequenceValue
	switch cursor.indexOf(3) {
	case 0:
		sep = sequenceValue{kind: sequenceString, text: "", cells: xoClean(0)}
	case 1:
		sep = xoPick(cursor, values, sequenceString)
	default:
		sep = sequenceValue{kind: sequenceString, text: ",", cells: xoClean(1)}
	}
	if total+len(sep.text)*len(elements) > xoMaxOutput {
		sep = sequenceValue{kind: sequenceString, text: "", cells: xoClean(0)}
	}
	concatMode := sep.text == "" && len(elements) <= xoInputs && cursor.next()&1 == 0
	var native string
	if concatMode {
		for _, element := range elements {
			native += element // runtime concatstrings alias semantics
		}
	} else {
		native = strings.Join(elements, sep.text)
	}
	desc := fmt.Sprintf("JoinString n=%d sep=%q concat=%v", len(elements), sep.text, concatMode)
	got := propagation.JoinString(elements, sep.text, native)
	if got != native {
		tb.Fatalf("%s changed value: %q vs %q", desc, got, native)
	}
	for index, element := range elements {
		if off, ok := xoStrOffset(element, got); ok {
			return one(xoString(got, xoSlice(cells[index], off, off+len(got)), true, desc))
		}
	}
	if len(elements) > xoInputs {
		parts := append(append([]xoCells(nil), cells[:xoInputs-1]...), sep.cells)
		return one(xoString(got, xoCoarse(len(got), parts...), false, desc+" coarse"))
	}
	var parts []xoCells
	for index := range elements {
		if index > 0 {
			parts = append(parts, sep.cells)
		}
		parts = append(parts, cells[index])
	}
	joined := xoConcat(parts...)
	if len(joined[0]) != len(got) {
		tb.Fatalf("%s oracle length mismatch", desc)
	}
	return one(xoString(got, joined, false, desc))
}

func xoReplaceString(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	input := xoPick(cursor, values, sequenceString)
	var old string
	switch cursor.indexOf(4) {
	case 0:
		old = ""
	case 1:
		old = string(xoSubstring(cursor, []byte(input.text)))
	case 2:
		old = xoPick(cursor, values, sequenceString).text
	default:
		old = "a"
	}
	var repl sequenceValue
	switch cursor.indexOf(3) {
	case 0:
		repl = sequenceValue{kind: sequenceString, text: "", cells: xoClean(0)}
	case 1:
		repl = sequenceValue{kind: sequenceString, text: "XY", cells: xoClean(2)}
	default:
		repl = xoPick(cursor, values, sequenceString)
	}
	count := []int{-1, 0, 1, 2, 3, 5, 40, -1}[cursor.indexOf(8)]
	desc := fmt.Sprintf("ReplaceString input=%q old=%q repl=%q n=%d", input.text, old, repl.text, count)
	if _, outLen := xoReplaceLen([]byte(input.text), []byte(old), []byte(repl.text), count); outLen > xoMaxOutput {
		return one(xoString(input.text, input.cells, true, "skip"))
	}
	expected, cells, matches := xoReplaceCells([]byte(input.text), input.cells, []byte(old), []byte(repl.text), repl.cells, count)
	if len(expected) > xoMaxOutput {
		return one(xoString(input.text, input.cells, true, "skip"))
	}
	native := strings.Replace(input.text, old, repl.text, count)
	if native != string(expected) {
		tb.Fatalf("%s oracle value differs: %q vs %q", desc, expected, native)
	}
	got := propagation.ReplaceString(input.text, old, repl.text, native, count)
	if got != native {
		tb.Fatalf("%s changed value", desc)
	}
	if off, ok := xoStrOffset(input.text, got); ok {
		return one(xoString(got, xoSlice(input.cells, off, off+len(got)), true, desc+" alias"))
	}
	if matches > xoMatches {
		return one(xoString(got, xoCoarse(len(got), input.cells, repl.cells), false, desc+" coarse"))
	}
	return one(xoString(got, cells, false, desc))
}

func xoRepeatString(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	input := xoPick(cursor, values, sequenceString)
	count := cursor.indexOf(6)
	if len(input.text)*count > xoMaxOutput {
		count = 1
	}
	desc := fmt.Sprintf("RepeatString len=%d n=%d", len(input.text), count)
	native := strings.Repeat(input.text, count)
	got := propagation.RepeatString(input.text, native, count)
	if got != native {
		tb.Fatalf("%s changed value", desc)
	}
	if off, ok := xoStrOffset(input.text, got); ok {
		return one(xoString(got, xoSlice(input.cells, off, off+len(got)), true, desc+" alias"))
	}
	parts := make([]xoCells, count)
	for index := range parts {
		parts[index] = input.cells
	}
	return one(xoString(got, xoConcat(parts...), false, desc))
}

func xoStringWindows(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	input := xoPick(cursor, values, sequenceString)
	var sep string
	switch cursor.indexOf(4) {
	case 0:
		sep = ""
	case 1:
		sep = string(xoSubstring(cursor, []byte(input.text)))
	case 2:
		sep = ","
	default:
		sep = "a"
	}
	var outputs []string
	mode := cursor.indexOf(5)
	switch mode {
	case 0:
		outputs = strings.Split(input.text, sep)
	case 1:
		outputs = strings.SplitAfter(input.text, sep)
	case 2:
		outputs = strings.SplitN(input.text, sep, cursor.indexOf(6)-1)
	case 3:
		outputs = strings.Fields(input.text)
	default:
		outputs = strings.FieldsFunc(input.text, func(r rune) bool { return !unicode.IsLetter(r) })
	}
	desc := fmt.Sprintf("StringWindows mode=%d input=%q sep=%q outputs=%d", mode, input.text, sep, len(outputs))
	propagation.StringWindows(input.text, outputs)
	var results []sequenceValue
	var keep []int
	for index, output := range outputs {
		if index >= xoWindows {
			break
		}
		off, ok := xoStrOffset(input.text, output)
		if !ok {
			if len(output) != 0 {
				tb.Fatalf("%s: non-alias non-empty output %d", desc, index)
			}
			continue
		}
		results = append(results, xoString(output, xoSlice(input.cells, off, off+len(output)), true, desc))
		if len(keep) < 2 && cursor.next()&1 == 0 {
			keep = append(keep, len(results)-1)
		}
	}
	return results, keep, desc
}

func xoStringWindow(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	input := xoPick(cursor, values, sequenceString)
	arg := string(xoSubstring(cursor, []byte(input.text)))
	var outputs []string
	mode := cursor.indexOf(6)
	switch mode {
	case 0:
		outputs = []string{strings.Trim(input.text, arg)}
	case 1:
		outputs = []string{strings.TrimSpace(input.text)}
	case 2:
		outputs = []string{strings.TrimPrefix(input.text, input.text[:cursor.indexOf(len(input.text)+1)])}
	case 3:
		outputs = []string{strings.TrimSuffix(input.text, input.text[cursor.indexOf(len(input.text)+1):])}
	case 4:
		before, after, _ := strings.Cut(input.text, arg)
		outputs = []string{before, after}
	default:
		outputs = []string{strings.TrimLeftFunc(input.text, func(r rune) bool { return r == utf8.RuneError || r == 0xe9 || r == 'a' })}
	}
	desc := fmt.Sprintf("StringWindow mode=%d input=%q arg=%q", mode, input.text, arg)
	var results []sequenceValue
	var keep []int
	for _, output := range outputs {
		propagation.StringWindow(input.text, output)
		off, ok := xoStrOffset(input.text, output)
		if !ok {
			continue
		}
		results = append(results, xoString(output, xoSlice(input.cells, off, off+len(output)), true, desc))
		keep = append(keep, len(results)-1)
	}
	return results, keep, desc
}

func xoCaseString(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	input := xoPick(cursor, values, sequenceString)
	var native string
	mode := cursor.indexOf(3)
	switch mode {
	case 0:
		native = strings.ToUpper(input.text)
	case 1:
		native = strings.ToLower(input.text)
	default:
		native = strings.ToTitle(input.text)
	}
	desc := fmt.Sprintf("CaseString mode=%d input=%q", mode, input.text)
	got := propagation.CaseString(input.text, native)
	if got != native {
		tb.Fatalf("%s changed value", desc)
	}
	if off, ok := xoStrOffset(input.text, got); ok {
		return one(xoString(got, xoSlice(input.cells, off, off+len(got)), true, desc+" alias"))
	}
	if len(got) == len(input.text) && xoASCII([]byte(input.text)) {
		return one(xoString(got, xoSlice(input.cells, 0, len(got)), false, desc+" exact"))
	}
	return one(xoString(got, xoCoarse(len(got), input.cells), false, desc+" coarse"))
}

func xoCopyString(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	input := xoPick(cursor, values, sequenceString)
	mode := cursor.indexOf(3)
	desc := fmt.Sprintf("CopyString mode=%d len=%d", mode, len(input.text))
	var got string
	switch mode {
	case 0:
		got = propagation.CopyString(input.text, strings.Clone(input.text))
	case 1:
		got = propagation.AdoptStringCopy(input.text, strings.Clone(input.text))
	default:
		got = propagation.CopyString(input.text, input.text)
	}
	if got != input.text {
		tb.Fatalf("%s changed value", desc)
	}
	if off, ok := xoStrOffset(input.text, got); ok {
		return one(xoString(got, xoSlice(input.cells, off, off+len(got)), true, desc+" alias"))
	}
	return one(xoString(got, xoSlice(input.cells, 0, len(got)), false, desc))
}

func xoCoarseString(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	input := xoPick(cursor, values, sequenceString)
	pairs := [][]string{{"a", "A"}, {"\u00e9", "e"}, {"zz", ""}, {",", ";;"}}[cursor.indexOf(4)]
	native := strings.NewReplacer(pairs...).Replace(input.text)
	desc := fmt.Sprintf("CoarseString replacer=%q input=%q", pairs, input.text)
	got := propagation.CoarseString(native, input.text)
	if got != native {
		tb.Fatalf("%s changed value", desc)
	}
	if off, ok := xoStrOffset(input.text, got); ok {
		return one(xoString(got, xoSlice(input.cells, off, off+len(got)), true, desc+" alias"))
	}
	return one(xoString(got, xoCoarse(len(got), input.cells), false, desc+" coarse"))
}

func xoBytesToString(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	input := xoPick(cursor, values, sequenceBytes)
	native := string(input.data)
	desc := fmt.Sprintf("BytesToString len=%d", len(input.data))
	got := propagation.BytesToString(input.data, native)
	if got != native {
		tb.Fatalf("%s changed value", desc)
	}
	return one(xoString(got, xoSlice(input.cells, 0, len(got)), false, desc))
}

func xoJoinBytes(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	n := 1 + cursor.indexOf(20)
	elements := make([][]byte, 0, n)
	cells := make([]xoCells, 0, n)
	total := 0
	for range n {
		var v sequenceValue
		switch cursor.indexOf(6) {
		case 0:
			v = sequenceValue{kind: sequenceBytes, data: nil, cells: xoClean(0)}
		case 1:
			v = sequenceValue{kind: sequenceBytes, data: []byte("ab"), cells: xoClean(2)}
		default:
			v = xoPick(cursor, values, sequenceBytes)
		}
		if total+len(v.data) > xoMaxOutput/2 {
			break
		}
		total += len(v.data)
		elements = append(elements, v.data)
		cells = append(cells, v.cells)
	}
	var sep sequenceValue
	switch cursor.indexOf(3) {
	case 0:
		sep = sequenceValue{kind: sequenceBytes, cells: xoClean(0)}
	case 1:
		sep = xoPick(cursor, values, sequenceBytes)
	default:
		sep = sequenceValue{kind: sequenceBytes, data: []byte(","), cells: xoClean(1)}
	}
	if total+len(sep.data)*len(elements) > xoMaxOutput {
		sep = sequenceValue{kind: sequenceBytes, cells: xoClean(0)}
	}
	desc := fmt.Sprintf("JoinBytes n=%d sep=%q", len(elements), sep.data)
	native := bytes.Join(elements, sep.data)
	want := bytes.Clone(native)
	got := propagation.JoinBytes(elements, sep.data, native)
	if !bytes.Equal(got, want) {
		tb.Fatalf("%s changed value", desc)
	}
	if len(elements) > xoInputs {
		parts := append(append([]xoCells(nil), cells[:xoInputs-1]...), sep.cells)
		return one(xoBytes(got, xoCoarse(len(got), parts...), false, desc+" coarse"))
	}
	var parts []xoCells
	for index := range elements {
		if index > 0 {
			parts = append(parts, sep.cells)
		}
		parts = append(parts, cells[index])
	}
	return one(xoBytes(got, xoConcat(parts...), false, desc))
}

func xoReplaceBytes(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	input := xoPick(cursor, values, sequenceBytes)
	var old []byte
	switch cursor.indexOf(4) {
	case 0:
		old = nil
	case 1:
		old = xoSubstring(cursor, input.data)
	case 2:
		old = xoPick(cursor, values, sequenceBytes).data
	default:
		old = []byte("a")
	}
	var repl sequenceValue
	switch cursor.indexOf(3) {
	case 0:
		repl = sequenceValue{kind: sequenceBytes, cells: xoClean(0)}
	case 1:
		repl = sequenceValue{kind: sequenceBytes, data: []byte("XY"), cells: xoClean(2)}
	default:
		repl = xoPick(cursor, values, sequenceBytes)
	}
	count := []int{-1, 0, 1, 2, 3, 5, 40, -1}[cursor.indexOf(8)]
	desc := fmt.Sprintf("ReplaceBytes input=%q old=%q repl=%q n=%d", input.data, old, repl.data, count)
	if _, outLen := xoReplaceLen(input.data, old, repl.data, count); outLen > xoMaxOutput {
		return one(xoBytes(input.data, input.cells, true, "skip"))
	}
	expected, cells, matches := xoReplaceCells(input.data, input.cells, old, repl.data, repl.cells, count)
	if len(expected) > xoMaxOutput {
		return one(xoBytes(input.data, input.cells, true, "skip"))
	}
	native := bytes.Replace(input.data, old, repl.data, count)
	if !bytes.Equal(native, expected) {
		tb.Fatalf("%s oracle value differs", desc)
	}
	got := propagation.ReplaceBytes(input.data, old, repl.data, native, count)
	if !bytes.Equal(got, expected) {
		tb.Fatalf("%s changed value", desc)
	}
	if matches > xoMatches {
		return one(xoBytes(got, xoCoarse(len(got), input.cells, repl.cells), false, desc+" coarse"))
	}
	return one(xoBytes(got, cells, false, desc))
}

func xoRepeatBytes(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	input := xoPick(cursor, values, sequenceBytes)
	count := cursor.indexOf(6)
	if len(input.data)*count > xoMaxOutput {
		count = 1
	}
	desc := fmt.Sprintf("RepeatBytes len=%d n=%d", len(input.data), count)
	native := bytes.Repeat(input.data, count)
	got := propagation.RepeatBytes(input.data, native, count)
	if !bytes.Equal(got, bytes.Repeat(input.data, count)) {
		tb.Fatalf("%s changed value", desc)
	}
	if off, ok := xoBytesOffset(input.data, got); ok {
		return one(xoBytes(got, xoSlice(input.cells, off, off+len(got)), true, desc+" alias"))
	}
	parts := make([]xoCells, count)
	for index := range parts {
		parts[index] = input.cells
	}
	return one(xoBytes(got, xoConcat(parts...), false, desc))
}

func xoByteWindows(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	input := xoPick(cursor, values, sequenceBytes)
	var sep []byte
	switch cursor.indexOf(4) {
	case 0:
		sep = nil
	case 1:
		sep = xoSubstring(cursor, input.data)
	case 2:
		sep = []byte(",")
	default:
		sep = []byte("a")
	}
	var outputs [][]byte
	mode := cursor.indexOf(5)
	switch mode {
	case 0:
		outputs = bytes.Split(input.data, sep)
	case 1:
		outputs = bytes.SplitAfter(input.data, sep)
	case 2:
		outputs = bytes.SplitN(input.data, sep, cursor.indexOf(6)-1)
	case 3:
		outputs = bytes.Fields(input.data)
	default:
		outputs = bytes.FieldsFunc(input.data, func(r rune) bool { return !unicode.IsLetter(r) })
	}
	desc := fmt.Sprintf("ByteWindows mode=%d input=%q sep=%q outputs=%d", mode, input.data, sep, len(outputs))
	propagation.ByteWindows(input.data, outputs)
	var results []sequenceValue
	var keep []int
	for index, output := range outputs {
		if index >= xoWindows {
			break
		}
		off, ok := xoBytesOffset(input.data, output)
		if !ok {
			if len(output) != 0 {
				tb.Fatalf("%s: non-alias non-empty output %d", desc, index)
			}
			continue
		}
		results = append(results, xoBytes(output, xoSlice(input.cells, off, off+len(output)), true, desc))
		if len(keep) < 2 && cursor.next()&1 == 0 {
			keep = append(keep, len(results)-1)
		}
	}
	return results, keep, desc
}

func xoByteWindow(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	input := xoPick(cursor, values, sequenceBytes)
	arg := xoSubstring(cursor, input.data)
	var outputs [][]byte
	mode := cursor.indexOf(6)
	switch mode {
	case 0:
		outputs = [][]byte{bytes.Trim(input.data, string(arg))}
	case 1:
		outputs = [][]byte{bytes.TrimSpace(input.data)}
	case 2:
		outputs = [][]byte{bytes.TrimPrefix(input.data, input.data[:cursor.indexOf(len(input.data)+1)])}
	case 3:
		outputs = [][]byte{bytes.TrimSuffix(input.data, input.data[cursor.indexOf(len(input.data)+1):])}
	case 4:
		before, after, _ := bytes.Cut(input.data, arg)
		outputs = [][]byte{before, after}
	default:
		outputs = [][]byte{bytes.TrimLeftFunc(input.data, func(r rune) bool { return r == utf8.RuneError || r == 0xe9 || r == 'a' })}
	}
	desc := fmt.Sprintf("ByteWindow mode=%d input=%q arg=%q", mode, input.data, arg)
	var results []sequenceValue
	var keep []int
	for _, output := range outputs {
		propagation.ByteWindow(input.data, output)
		off, ok := xoBytesOffset(input.data, output)
		if !ok {
			continue
		}
		results = append(results, xoBytes(output, xoSlice(input.cells, off, off+len(output)), true, desc))
		keep = append(keep, len(results)-1)
	}
	return results, keep, desc
}

func xoCaseBytes(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	input := xoPick(cursor, values, sequenceBytes)
	var native, want []byte
	mode := cursor.indexOf(3)
	switch mode {
	case 0:
		native, want = bytes.ToUpper(input.data), bytes.ToUpper(input.data)
	case 1:
		native, want = bytes.ToLower(input.data), bytes.ToLower(input.data)
	default:
		native, want = bytes.ToTitle(input.data), bytes.ToTitle(input.data)
	}
	desc := fmt.Sprintf("CaseBytes mode=%d input=%q", mode, input.data)
	got := propagation.CaseBytes(input.data, native)
	if !bytes.Equal(got, want) {
		tb.Fatalf("%s changed value", desc)
	}
	if off, ok := xoBytesOffset(input.data, got); ok {
		return one(xoBytes(got, xoSlice(input.cells, off, off+len(got)), true, desc+" alias"))
	}
	if len(got) == len(input.data) && xoASCII(input.data) {
		return one(xoBytes(got, xoSlice(input.cells, 0, len(got)), false, desc+" exact"))
	}
	return one(xoBytes(got, xoCoarse(len(got), input.cells), false, desc+" coarse"))
}

func xoCopyBytes(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	input := xoPick(cursor, values, sequenceBytes)
	mode := cursor.indexOf(2)
	desc := fmt.Sprintf("CopyBytes mode=%d len=%d", mode, len(input.data))
	var got []byte
	if mode == 0 {
		got = propagation.CopyBytes(input.data, bytes.Clone(input.data))
	} else {
		got = propagation.CopyBytes(input.data, input.data)
	}
	if !bytes.Equal(got, input.data) {
		tb.Fatalf("%s changed value", desc)
	}
	if off, ok := xoBytesOffset(input.data, got); ok {
		return one(xoBytes(got, xoSlice(input.cells, off, off+len(got)), true, desc+" alias"))
	}
	return one(xoBytes(got, xoSlice(input.cells, 0, len(got)), false, desc))
}

func xoValidUTF8(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	input := xoPick(cursor, values, sequenceBytes)
	var repl sequenceValue
	switch cursor.indexOf(3) {
	case 0:
		repl = sequenceValue{kind: sequenceBytes, cells: xoClean(0)}
	case 1:
		repl = sequenceValue{kind: sequenceBytes, data: []byte("\uFFFD"), cells: xoClean(3)}
	default:
		repl = xoPick(cursor, values, sequenceBytes)
	}
	desc := fmt.Sprintf("ValidUTF8Bytes input=%q repl=%q", input.data, repl.data)
	if len(input.data)+xoValidUTF8Runs(input.data)*len(repl.data) > xoMaxOutput {
		return one(xoBytes(input.data, input.cells, true, "skip"))
	}
	expected, cells, runs := xoValidUTF8Cells(input.data, input.cells, repl.data, repl.cells)
	if len(expected) > xoMaxOutput {
		return one(xoBytes(input.data, input.cells, true, "skip"))
	}
	native := bytes.ToValidUTF8(input.data, repl.data)
	if !bytes.Equal(native, expected) {
		tb.Fatalf("%s oracle value differs: %q vs %q", desc, expected, native)
	}
	got := propagation.ValidUTF8Bytes(input.data, repl.data, native)
	if !bytes.Equal(got, expected) {
		tb.Fatalf("%s changed value", desc)
	}
	if runs > xoMatches {
		return one(xoBytes(got, xoCoarse(len(got), input.cells, repl.cells), false, desc+" coarse"))
	}
	return one(xoBytes(got, cells, false, desc))
}

func xoMapBytes(tb testing.TB, cursor *sequenceCursor, values []sequenceValue) ([]sequenceValue, []int, string) {
	input := xoPick(cursor, values, sequenceBytes)
	mappings := []func(rune) rune{
		func(r rune) rune { return r },
		unicode.ToUpper,
		func(r rune) rune {
			if r == 'a' {
				return -1
			}
			return r
		},
	}
	mode := cursor.indexOf(len(mappings))
	native := bytes.Map(mappings[mode], input.data)
	want := bytes.Clone(native)
	desc := fmt.Sprintf("CoarseBytes(Map) mode=%d input=%q", mode, input.data)
	got := propagation.CoarseBytes(native, input.data)
	if !bytes.Equal(got, want) {
		tb.Fatalf("%s changed value", desc)
	}
	return one(xoBytes(got, xoCoarse(len(got), input.cells), false, desc))
}
