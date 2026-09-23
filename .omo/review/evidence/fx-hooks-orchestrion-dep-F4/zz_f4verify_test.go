// Phase-3 reproducer for hooks-orchestrion-dep-F4.
package propagation_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// f4ControlConcat: plain "~string" constraint (shape the existing woven tests cover).
// f4Intersected* constrains T by intersection: type set = (~string | ~int) AND ~string == ~string.
// Slicing and "+" compiling at all proves the final type set is string-only.
func f4ControlConcat[T ~string](value T) T { return value + "!" }

func f4IntersectedConcat[T interface {
	~string | ~int
	~string
}](value T) T {
	return value + "!"
}

func f4IntersectedSlice[T interface {
	~string | ~int
	~string
}](value T) T {
	return value[1:]
}

// f4IntersectedBytes: type set = (~[]byte | ~[]int) AND ~[]byte == ~[]byte.
func f4IntersectedBytes[T interface {
	~[]byte | ~[]int
	~[]byte
}](value T) T {
	return value[1:]
}

func TestF4IntersectedCoreTypeKeepsProvenance(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires woven operator advice")
	}
	ctx := beginNativePropagation(t)
	source := nativeStringSource(t, ctx, "f4-string", "attack")
	bytes := nativeByteSource(t, ctx, "f4-bytes", []byte("attack"))

	t.Run("control plain ~string generic concat is advised", func(t *testing.T) {
		got := f4ControlConcat(source)
		require.Equal(t, "attack!", got)
		t.Logf("control tainted: %v", taint.IsTaintedString(got))
		require.True(t, taint.IsTaintedString(got),
			"positive control: plain ~string generic concat must retain taint")
	})

	t.Run("intersected ~string|~int & ~string concat", func(t *testing.T) {
		got := f4IntersectedConcat(source)
		require.Equal(t, "attack!", got)
		t.Logf("intersected concat tainted: %v", taint.IsTaintedString(got))
		require.True(t, taint.IsTaintedString(got),
			"intersected constraint with string-only type set must retain taint")
	})

	t.Run("intersected ~string|~int & ~string slice", func(t *testing.T) {
		got := f4IntersectedSlice(source)
		require.Equal(t, "ttack", got)
		t.Logf("intersected string slice tainted: %v", taint.IsTaintedString(got))
		require.True(t, taint.IsTaintedString(got),
			"intersected constraint with string-only type set must retain taint")
	})

	t.Run("intersected ~[]byte|~[]int & ~[]byte slice", func(t *testing.T) {
		got := f4IntersectedBytes(bytes)
		require.Equal(t, []byte("ttack"), []byte(got))
		t.Logf("intersected byte slice tainted: %v", taint.IsTaintedBytes([]byte(got)))
		require.True(t, taint.IsTaintedBytes([]byte(got)),
			"intersected constraint with []byte-only type set must retain taint")
	})
}
