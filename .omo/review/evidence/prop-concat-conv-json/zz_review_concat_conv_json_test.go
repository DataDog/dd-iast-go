package propagation_test

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

func reviewConcat(ops []string, result string) string {
	o := ops
	switch len(ops) {
	case 2:
		return propagation.Concat2(o[0], o[1], result)
	case 3:
		return propagation.Concat3(o[0], o[1], o[2], result)
	case 4:
		return propagation.Concat4(o[0], o[1], o[2], o[3], result)
	case 5:
		return propagation.Concat5(o[0], o[1], o[2], o[3], o[4], result)
	case 6:
		return propagation.Concat6(o[0], o[1], o[2], o[3], o[4], o[5], result)
	case 7:
		return propagation.Concat7(o[0], o[1], o[2], o[3], o[4], o[5], o[6], result)
	case 8:
		return propagation.Concat8(o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], result)
	case 9:
		return propagation.Concat9(o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], result)
	case 10:
		return propagation.Concat10(o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], o[9], result)
	case 11:
		return propagation.Concat11(o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], o[9], o[10], result)
	case 12:
		return propagation.Concat12(o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], o[9], o[10], o[11], result)
	case 13:
		return propagation.Concat13(o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], o[9], o[10], o[11], o[12], result)
	case 14:
		return propagation.Concat14(o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], o[9], o[10], o[11], o[12], o[13], result)
	case 15:
		return propagation.Concat15(o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], o[9], o[10], o[11], o[12], o[13], o[14], result)
	case 16:
		return propagation.Concat16(o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7], o[8], o[9], o[10], o[11], o[12], o[13], o[14], o[15], result)
	}
	panic("arity")
}

// perByte expands ranges to a per-byte source map (0 = clean).
func perByte(rs []ranges.Range, n int) []ranges.SourceID {
	out := make([]ranges.SourceID, n)
	for _, r := range rs {
		for i := r.Start; i < r.Start+r.Length && int(i) < n; i++ {
			out[i] = r.SourceID
		}
	}
	return out
}

// TestReviewConcatOffsetsProperty checks 2-16 operand concatenation offsets
// against a per-byte oracle with empty, clean, and multi-range tainted operands.
func TestReviewConcatOffsetsProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	s, _ := beginScope(t)
	compared := 0
	defer func() { fmt.Printf("CONCAT-PROPERTY: tainted comparisons=%d of 3000\n", compared) }()
	for iter := 0; iter < 3000; iter++ {
		func() {
			owner := s.Acquire()
			require.False(t, owner.Disabled())
			defer owner.Finish()
			n := 2 + rng.Intn(15)
			ops := make([]string, n)
			var expected []ranges.SourceID
			budget := 9 // stay under the default 10-range limit
			for i := range ops {
				kind := rng.Intn(4)
				length := rng.Intn(6)
				if kind == 0 {
					length = 0
				}
				raw := strings.Repeat(string(rune('a'+i)), length)
				perOp := make([]ranges.SourceID, length)
				if kind == 3 && length >= 2 && budget > 0 {
					start := uint32(rng.Intn(length))
					l := uint32(1 + rng.Intn(length-int(start)))
					src := ranges.SourceID(1 + rng.Intn(5))
					rs := []ranges.Range{{Start: start, Length: l, SourceID: src}}
					budget--
					var v string
					v, _ = taintString(t, owner, raw, rs)
					raw = v
					copy(perOp, perByte(rs, length))
				} else {
					raw = strings.Clone(raw)
				}
				ops[i] = raw
				expected = append(expected, perOp...)
			}
			native := strings.Join(ops, "")
			got := reviewConcat(ops, native)
			require.Equal(t, native, got, "value must be preserved")
			rs := lookupRanges(s, got)
			var got2 []ranges.SourceID
			if rs != nil {
				got2 = perByte(rs, len(got))
			} else {
				got2 = make([]ranges.SourceID, len(got))
			}
			// canonical merges adjacent equal-source ranges; per-byte compare is exact.
			wantAny := false
			for _, id := range expected {
				if id != 0 {
					wantAny = true
				}
			}
			if !wantAny {
				require.Empty(t, rs, "iter %d: clean concat must stay clean", iter)
				return
			}
			if len(got) < 2 {
				return
			}
			compared++
			require.Equal(t, expected, got2, "iter %d n=%d ops=%q ranges=%v", iter, n, ops, rs)
		}()
	}
}

// TestReviewConcatAliasSingleNonEmpty covers the "" + s runtime alias path.
func TestReviewConcatAliasSingleNonEmpty(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	v, _ := taintString(t, owner, "attack", []ranges.Range{{Start: 1, Length: 3, SourceID: 4}})
	for n := 2; n <= 16; n++ {
		ops := make([]string, n)
		ops[n/2] = v
		got := reviewConcat(ops, v) // native concatstrings returns the only non-empty operand
		require.Equal(t, v, got)
		require.Equal(t, []ranges.Range{{Start: 1, Length: 3, SourceID: 4}}, lookupRanges(s, got), "n=%d", n)
	}
}

func TestReviewBytesToStringCopiesWindowRanges(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	root, ref := taintBytes(t, owner, []byte("xxattackyy"), []ranges.Range{{Start: 2, Length: 6, SourceID: 3}})
	_ = ref
	// full root
	got := propagation.BytesToString(root, string(root))
	require.Equal(t, []ranges.Range{{Start: 2, Length: 6, SourceID: 3}}, lookupRanges(s, got))
	// derived window with spare capacity after it
	window := root[1:5]
	propagation.ByteWindow(root, window)
	got = propagation.BytesToString(window, string(window))
	require.Equal(t, []ranges.Range{{Start: 1, Length: 3, SourceID: 3}}, lookupRanges(s, got))
	// length mismatch refuses
	got = propagation.BytesToString(root, string(root[:4]))
	require.Empty(t, lookupRanges(s, got))
}

func TestReviewJSONStringBoundsAndEscapes(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)

	// literal == whole document (offset 0, length == len(document)).
	doc, _ := taintBytes(t, owner, []byte(`"attack"`), []ranges.Range{{Start: 0, Length: 8, SourceID: 2}})
	got, ok := propagation.JSONString(doc, doc, strings.Clone("attack"))
	require.True(t, ok)
	require.Equal(t, []ranges.Range{{Length: 6, SourceID: 2}}, lookupRanges(s, got))

	// \u escapes: literal is 14 bytes, result is 2 bytes; coarse whole-value range.
	raw := `{"v":"\u0041\u0042"}`
	doc2, _ := taintBytes(t, owner, []byte(raw), []ranges.Range{{Start: 0, Length: uint32(len(raw)), SourceID: 5}})
	lit := doc2[5 : len(doc2)-1]
	require.Equal(t, `"\u0041\u0042"`, string(lit))
	got, ok = propagation.JSONString(doc2, lit, strings.Clone("AB"))
	require.True(t, ok)
	require.Equal(t, []ranges.Range{{Length: 2, SourceID: 5}}, lookupRanges(s, got))

	// Long result shorter than literal and longer (multi-byte UTF-8 decoded from \u escape).
	raw3 := `{"v":"\u00e9\u00e9"}`
	doc3, _ := taintBytes(t, owner, []byte(raw3), []ranges.Range{{Start: 0, Length: uint32(len(raw3)), SourceID: 6}})
	got, ok = propagation.JSONString(doc3, doc3[5:len(doc3)-1], strings.Clone("éé"))
	require.True(t, ok)
	require.Equal(t, []ranges.Range{{Length: 4, SourceID: 6}}, lookupRanges(s, got))

	// Document is a derived window of a larger root: offsets are window-relative.
	raw4 := `PREFIX{"v":"attack"}`
	root4, _ := taintBytes(t, owner, []byte(raw4), []ranges.Range{{Start: 12, Length: 6, SourceID: 8}})
	doc4 := root4[6:]
	propagation.ByteWindow(root4, doc4)
	got, ok = propagation.JSONString(doc4, doc4[5:13], strings.Clone("attack"))
	require.True(t, ok)
	require.Equal(t, []ranges.Range{{Length: 6, SourceID: 8}}, lookupRanges(s, got))
	// A literal outside the document window (inside the root prefix) is rejected.
	got, ok = propagation.JSONString(doc4, root4[0:6], strings.Clone("PREFIX"))
	require.False(t, ok)
	require.Empty(t, lookupRanges(s, got))

	// Observation: taint intersecting only the delimiting quote coarsens the whole value.
	raw5 := `{"v":"clean"}`
	doc5, _ := taintBytes(t, owner, []byte(raw5), []ranges.Range{{Start: 11, Length: 1, SourceID: 9}})
	got, ok = propagation.JSONString(doc5, doc5[5:12], strings.Clone("clean"))
	fmt.Printf("QUOTE-ONLY: propagated=%v ranges=%v\n", ok, lookupRanges(s, got))
}

func TestReviewJSONStringTwoOwners(t *testing.T) {
	s, _ := beginScope(t)
	a := acquireOwner(t, s)
	b := acquireOwner(t, s)
	doc, _ := taintBytes(t, a, []byte(`{"v":"attack"}`), []ranges.Range{{Start: 6, Length: 6, SourceID: 1}})
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Start: 0, Length: uint32(cap(doc)), SourceID: 2}}, uint32(cap(doc))).Valid)
	_, ok := b.AdoptBytes(doc, &set)
	require.True(t, ok)
	got, ok := propagation.JSONString(doc, doc[5:13], strings.Clone("attack"))
	require.True(t, ok)
	key, _ := store.StringKey(got)
	require.Equal(t, 2, lookupEntryCount(s, key))
}
