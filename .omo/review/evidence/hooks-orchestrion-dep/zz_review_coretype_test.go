package propagation_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

func reviewIntersectionConcat[T interface {
	~string | ~int
	~string
}](value T) T {
	return value + "!"
}

func reviewIntersectionSlice[T interface {
	~string | ~int
	~string
}](value T) T {
	return value[1:]
}

func reviewIntersectionByteSlice[T interface {
	~[]byte | ~[]int
	~[]byte
}](value T) T {
	return value[1:]
}

func TestReviewIntersectionCoreTypeRetainsProvenance(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires woven operator advice")
	}
	ctx := beginNativePropagation(t)
	const name = "core-intersection"
	source := nativeStringSource(t, ctx, name, "attack")
	want := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: name},
		Value:  "attack",
	}
	t.Run("string concat", func(t *testing.T) {
		gotConcat := reviewIntersectionConcat(source)
		require.Equal(t, "attack!", gotConcat)
		requireNativeStringRanges(t, gotConcat, nativeExpectedRange{
			length: 6,
			source: want,
			marks:  []taint.VulnerabilityType{taint.VulnerabilityTypeSqlInjection, taint.VulnerabilityTypeCommandInjection},
		})
	})
	t.Run("string slice", func(t *testing.T) {
		gotSlice := reviewIntersectionSlice(source)
		require.Equal(t, "ttack", gotSlice)
		requireNativeStringRanges(t, gotSlice, nativeExpectedRange{
			length: 5,
			source: want,
			marks:  []taint.VulnerabilityType{taint.VulnerabilityTypeSqlInjection, taint.VulnerabilityTypeCommandInjection},
		})
	})

	bytes := nativeByteSource(t, ctx, "core-byte", []byte("attack"))
	t.Run("byte slice", func(t *testing.T) {
		gotBytes := reviewIntersectionByteSlice(bytes)
		require.Equal(t, []byte("ttack"), []byte(gotBytes))
		requireNativeByteRanges(t, []byte(gotBytes), nativeExpectedRange{
			length: 5,
			source: taint.SourceValue{
				Source: taint.Source{Origin: taint.OriginHttpRequestBody, Name: "core-byte"},
				Value:  "attack",
			},
			marks: []taint.VulnerabilityType{taint.VulnerabilityTypeSqlInjection, taint.VulnerabilityTypeCommandInjection},
		})
	})
}
