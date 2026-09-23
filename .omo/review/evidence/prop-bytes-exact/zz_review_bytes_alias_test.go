package propagation_test

import (
	"bytes"
	"testing"
	"unsafe"

	wrapped "github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestReviewResliceWithinCapacityPreservesRanges(t *testing.T) {
	for _, mode := range []string{"two-index", "three-index", "clean-prefix", "empty-prefix"} {
		t.Run(mode, func(t *testing.T) {
			// Given: one bounded managed allocation; no mutations or saturation.
			s, _ := beginScope(t)
			owner := acquireOwner(t, s)
			input, _ := taintBytes(t, owner, []byte("01234567"), []ranges.Range{
				{Start: 2, Length: 4, SourceID: 7, Marks: 6},
			})
			short := wrapped.BytesSliceFull(input, 0, 3, 7)
			require.Equal(t, []ranges.Range{{Start: 2, Length: 1, SourceID: 7, Marks: 6}}, lookupByteRanges(s, short))
			if mode == "clean-prefix" {
				short = wrapped.BytesSliceFull(input, 0, 2, 7)
			} else if mode == "empty-prefix" {
				short = wrapped.BytesSliceFull(input, 1, 1, 7)
			}
			charged := owner.Charged()

			// When: a supported slice exposes existing bytes up to capacity.
			var result []byte
			var native []byte
			if mode == "two-index" {
				native = short[1:6]
				result = wrapped.BytesSliceBounds(short, 1, 6)
			} else if mode == "empty-prefix" {
				native = short[:5:6]
				result = wrapped.BytesSliceFullZero(short, 5, 6)
			} else {
				native = short[1:6:7]
				result = wrapped.BytesSliceFull(short, 1, 6, 7)
			}
			converted := wrapped.BytesToString(result)

			// Then: application behavior and exact provenance both survive.
			require.Equal(t, []byte("12345"), result)
			require.Equal(t, cap(native), cap(result))
			require.True(t, unsafe.SliceData(native) == unsafe.SliceData(result))
			require.Equal(t, charged, owner.Charged(), "derivation must not allocate a root")
			want := []ranges.Range{{Start: 1, Length: 4, SourceID: 7, Marks: 6}}
			t.Logf("short len=%d cap=%d, result=%q len=%d cap=%d, byte ranges=%v, string ranges=%v, want=%v",
				len(short), cap(short), result, len(result), cap(result), lookupByteRanges(s, result), lookupRanges(s, converted), want)
			require.Equal(t, want, lookupByteRanges(s, result))
			require.Equal(t, want, lookupRanges(s, converted))
		})
	}
}

func TestReviewInLengthWindowsAndFreshCopies(t *testing.T) {
	// Given.
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input, ref := taintBytes(t, owner, []byte("ab-cd-ef"), []ranges.Range{
		{Start: 1, Length: 3, SourceID: 3, Marks: 6},
	})
	window := wrapped.BytesSliceFull(input, 1, 5, 6)
	want := []ranges.Range{{Length: 3, SourceID: 3, Marks: 6}}
	require.Equal(t, 4, len(window))
	require.Equal(t, 5, cap(window))
	require.Equal(t, want, lookupByteRanges(s, window))
	require.Equal(t, []ranges.Range{{Length: 1, SourceID: 3, Marks: 6}}, lookupByteRanges(s, wrapped.BytesSliceBounds(input, 1, 2)))
	clean := bytes.Clone(window)
	require.Empty(t, lookupByteRanges(s, clean), "byte-identical clean control")

	// When: audited fresh-result fast paths, including no-op transforms.
	outputs := map[string][]byte{
		"clone":      wrapped.BytesClone(window),
		"join-one":   wrapped.BytesJoin([][]byte{window}, []byte("unused")),
		"repeat-one": wrapped.BytesRepeat(window, 1),
		"replace-0":  wrapped.BytesReplace(window, []byte("-"), []byte("++"), 0),
		"replace-no": wrapped.BytesReplaceAll(window, []byte("missing"), []byte("++")),
		"lower-noop": wrapped.BytesToLower(window),
		"valid-noop": wrapped.BytesToValidUTF8(window, []byte("unused")),
	}
	converted := wrapped.BytesToString(window)
	require.Equal(t, want, lookupRanges(s, converted))
	for name, output := range outputs {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, window, output)
			require.True(t, unsafe.SliceData(output) != unsafe.SliceData(window))
			require.Equal(t, want, lookupByteRanges(s, output))
		})
	}

	// Then: a root-generation change kills aliases, not independent copies.
	copy(input, []byte("clean!!!"))
	var empty ranges.Set
	_, ok := owner.PublishBytesMutation(ref, input, &empty)
	require.True(t, ok)
	require.Empty(t, lookupByteRanges(s, input))
	require.Empty(t, lookupByteRanges(s, window))
	require.Equal(t, want, lookupRanges(s, converted), "immutable conversion snapshot")
	for name, output := range outputs {
		require.Equal(t, want, lookupByteRanges(s, output), name)
	}
	owner.Finish()
	require.Empty(t, lookupRanges(s, converted), "finished owner cannot taint a later request")
	for name, output := range outputs {
		require.Empty(t, lookupByteRanges(s, output), name)
	}
}

func TestReviewFailedMutationStillInvalidatesAliases(t *testing.T) {
	// Given.
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input, ref := taintBytes(t, owner, []byte("abcdef"), []ranges.Range{{Length: 6, SourceID: 2}})
	window := wrapped.BytesSliceFull(input, 1, 4, 5)
	require.NotEmpty(t, lookupByteRanges(s, window))

	// When: the supported store mutation is rejected after its generation claim.
	copy(input, []byte("CLEAN!"))
	_, ok := owner.PublishBytesMutation(ref, input, nil)

	// Then.
	require.False(t, ok)
	require.Empty(t, lookupByteRanges(s, input))
	require.Empty(t, lookupByteRanges(s, window))
	require.Zero(t, owner.Values())
}

func TestReviewSpareCapacityIsNotFalselyTainted(t *testing.T) {
	// Given: a complete allocation with a clean capacity tail.
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	input := make([]byte, 4, 8)
	copy(input, "data")
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, ranges.DefaultLimit, []ranges.Range{{Length: 4, SourceID: 1}}, 8).Valid)
	_, ok := owner.AdoptBytes(input, &set)
	require.True(t, ok)

	// When and then: root bounds prevent invented taint in the untouched tail.
	tail := input[4:8:8]
	propagation.ByteWindow(input, tail)
	require.Empty(t, lookupByteRanges(s, tail))
}
