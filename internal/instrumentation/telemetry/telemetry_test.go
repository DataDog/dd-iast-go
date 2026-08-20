package telemetry_test

import (
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaxCardinalities(t *testing.T) {
	require.LessOrEqual(t, len(constants.AllOrigins()), 32, "there should always be less than 32 origins")
	require.LessOrEqual(t, len(constants.AllVulnerabilityTypes()), 64, "there should always be less than 64 vulnerability types")
}

func TestExecutedSource(t *testing.T) {
	origins := constants.AllOrigins()

	expected := make(map[constants.Origin]uint64, len(origins))

	rv := reflect.ValueOf(&telemetry.ExecutedSource).Elem()
	for name, origin := range origins {
		field := rv.FieldByName(name)
		if !assert.True(t, field.IsValid(), "missing field: %T.%s", &telemetry.ExecutedSource, name) {
			continue
		}
		actual := field.Addr().Interface()
		ctr, ok := actual.(*atomic.Uint64)
		if !assert.True(t, ok, "field %T.%s is %T, not %T", &telemetry.ExecutedSource, name, actual, ctr) {
			continue
		}

		t.Cleanup(func() { ctr.Store(0) })
		val := uint64(origin)*37 + 1
		ctr.Store(val)
		expected[origin] = val
	}

	for origin, ctr := range telemetry.ExecutedSource.Each {
		assert.Equal(t, expected[origin], ctr.Load())
		delete(expected, origin)
	}
	assert.Empty(t, expected, "some origins were not visited by Each: %v", expected)
}

func TestExecutedSink(t *testing.T) {
	vulnTypes := constants.AllVulnerabilityTypes()

	expected := make(map[constants.VulnerabilityType]uint64, len(vulnTypes))

	rv := reflect.ValueOf(&telemetry.ExecutedSink).Elem()
	for name, vulnType := range vulnTypes {
		field := rv.FieldByName(name)
		if !assert.True(t, field.IsValid(), "missing field: %T.%s", &telemetry.ExecutedSink, name) {
			continue
		}
		actual := field.Addr().Interface()
		ctr, ok := actual.(*atomic.Uint64)
		if !assert.True(t, ok, "field %T.%s is %T, not %T", &telemetry.ExecutedSink, name, actual, ctr) {
			continue
		}

		t.Cleanup(func() { ctr.Store(0) })
		val := uint64(vulnType)*41 + 1
		ctr.Store(val)
		expected[vulnType] = val
	}

	for vulnType, ctr := range telemetry.ExecutedSink.Each {
		assert.Equal(t, expected[vulnType], ctr.Load())
		delete(expected, vulnType)
	}
	assert.Empty(t, expected, "some vulnerability types were not visited by Each: %v", expected)
}

// captureSourceOrder records the exact sequence of origins visited by a
// complete, uninterrupted range over telemetry.ExecutedSource.Each. It does
// not mutate any counter.
func captureSourceOrder(t *testing.T) []constants.Origin {
	t.Helper()
	var order []constants.Origin
	for origin := range telemetry.ExecutedSource.Each {
		order = append(order, origin)
	}
	return order
}

// captureSinkOrder records the exact sequence of vulnerability types visited
// by a complete, uninterrupted range over telemetry.ExecutedSink.Each. It does
// not mutate any counter.
func captureSinkOrder(t *testing.T) []constants.VulnerabilityType {
	t.Helper()
	var order []constants.VulnerabilityType
	for vulnType := range telemetry.ExecutedSink.Each {
		order = append(order, vulnType)
	}
	return order
}

func TestExecutedSourceEachVisitsExactlyAllOrigins(t *testing.T) {
	order := captureSourceOrder(t)

	all := constants.AllOrigins()
	require.Len(t, order, len(all), "the complete iteration order must have exactly one entry per origin")

	seen := make(map[constants.Origin]bool, len(order))
	for _, origin := range order {
		require.False(t, seen[origin], "origin %s was visited more than once", origin)
		seen[origin] = true
	}
	for name, origin := range all {
		require.True(t, seen[origin], "origin %s (%s) was never visited", name, origin)
	}
}

func TestExecutedSinkEachVisitsExactlyAllVulnerabilityTypes(t *testing.T) {
	order := captureSinkOrder(t)

	all := constants.AllVulnerabilityTypes()
	require.Len(t, order, len(all), "the complete iteration order must have exactly one entry per vulnerability type")

	seen := make(map[constants.VulnerabilityType]bool, len(order))
	for _, vulnType := range order {
		require.False(t, seen[vulnType], "vulnerability type %s was visited more than once", vulnType)
		seen[vulnType] = true
	}
	for name, vulnType := range all {
		require.True(t, seen[vulnType], "vulnerability type %s (%s) was never visited", name, vulnType)
	}
}

// TestExecutedSourceEachRangeBreaksAtEveryPoint exercises an actual
// `for ... range telemetry.ExecutedSource.Each` loop and breaks at every
// possible position in the captured order. If any `yield` call inside `Each`
// were missing its `return` after being told to stop, the range runtime would
// invoke the already-stopped iterator function again and panic; this test
// would fail (via panic) rather than silently pass.
func TestExecutedSourceEachRangeBreaksAtEveryPoint(t *testing.T) {
	order := captureSourceOrder(t)
	require.NotEmpty(t, order)

	for i := range order {
		t.Run(fmt.Sprintf("break_at_%d_%s", i, order[i]), func(t *testing.T) {
			var visited []constants.Origin
			for origin := range telemetry.ExecutedSource.Each {
				visited = append(visited, origin)
				if origin == order[i] {
					break
				}
			}
			require.Equal(t, order[:i+1], visited)
		})
	}
}

// TestExecutedSinkEachRangeBreaksAtEveryPoint is the VulnerabilityType
// equivalent of TestExecutedSourceEachRangeBreaksAtEveryPoint.
func TestExecutedSinkEachRangeBreaksAtEveryPoint(t *testing.T) {
	order := captureSinkOrder(t)
	require.NotEmpty(t, order)

	for i := range order {
		t.Run(fmt.Sprintf("break_at_%d_%s", i, order[i]), func(t *testing.T) {
			var visited []constants.VulnerabilityType
			for vulnType := range telemetry.ExecutedSink.Each {
				visited = append(visited, vulnType)
				if vulnType == order[i] {
					break
				}
			}
			require.Equal(t, order[:i+1], visited)
		})
	}
}

// TestExecutedSourceEachCallbackStopsOnFalse verifies that a caller invoking
// Each directly (not through range syntax) and returning false from the
// callback stops further callbacks from being made.
func TestExecutedSourceEachCallbackStopsOnFalse(t *testing.T) {
	order := captureSourceOrder(t)
	require.NotEmpty(t, order)
	stopAfter := len(order)/2 + 1

	var visited []constants.Origin
	telemetry.ExecutedSource.Each(func(origin constants.Origin, _ *atomic.Uint64) bool {
		visited = append(visited, origin)
		return len(visited) < stopAfter
	})

	require.Equal(t, order[:stopAfter], visited)
}

// TestExecutedSinkEachCallbackStopsOnFalse is the VulnerabilityType
// equivalent of TestExecutedSourceEachCallbackStopsOnFalse.
func TestExecutedSinkEachCallbackStopsOnFalse(t *testing.T) {
	order := captureSinkOrder(t)
	require.NotEmpty(t, order)
	stopAfter := len(order)/2 + 1

	var visited []constants.VulnerabilityType
	telemetry.ExecutedSink.Each(func(vulnType constants.VulnerabilityType, _ *atomic.Uint64) bool {
		visited = append(visited, vulnType)
		return len(visited) < stopAfter
	})

	require.Equal(t, order[:stopAfter], visited)
}
