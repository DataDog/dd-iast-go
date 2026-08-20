package telemetry_test

import (
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

func TestMaxCardinalities(t *testing.T) {
	if got := len(constants.AllOrigins()); got > 32 {
		t.Errorf("origin count = %d, want at most 32", got)
	}
	if got := len(constants.AllVulnerabilityTypes()); got > 64 {
		t.Errorf("vulnerability type count = %d, want at most 64", got)
	}
}

func TestExecutedSource(t *testing.T) {
	origins := constants.AllOrigins()
	expected := make(map[constants.Origin]uint64, len(origins))

	rv := reflect.ValueOf(&telemetry.ExecutedSource).Elem()
	for name, origin := range origins {
		field := rv.FieldByName(name)
		if !field.IsValid() {
			t.Errorf("missing field: %T.%s", &telemetry.ExecutedSource, name)
			continue
		}
		actual := field.Addr().Interface()
		counter, ok := actual.(*atomic.Uint64)
		if !ok {
			t.Errorf("field %T.%s is %T, not %T", &telemetry.ExecutedSource, name, actual, counter)
			continue
		}

		t.Cleanup(func() { counter.Store(0) })
		value := uint64(origin)*37 + 1
		counter.Store(value)
		expected[origin] = value
	}

	for origin, counter := range telemetry.ExecutedSource.Each {
		if got, want := counter.Load(), expected[origin]; got != want {
			t.Errorf("counter for %s = %d, want %d", origin, got, want)
		}
		delete(expected, origin)
	}
	if len(expected) != 0 {
		t.Errorf("origins not visited by Each: %v", expected)
	}
}

func TestExecutedSink(t *testing.T) {
	vulnerabilityTypes := constants.AllVulnerabilityTypes()
	expected := make(map[constants.VulnerabilityType]uint64, len(vulnerabilityTypes))

	rv := reflect.ValueOf(&telemetry.ExecutedSink).Elem()
	for name, vulnerabilityType := range vulnerabilityTypes {
		field := rv.FieldByName(name)
		if !field.IsValid() {
			t.Errorf("missing field: %T.%s", &telemetry.ExecutedSink, name)
			continue
		}
		actual := field.Addr().Interface()
		counter, ok := actual.(*atomic.Uint64)
		if !ok {
			t.Errorf("field %T.%s is %T, not %T", &telemetry.ExecutedSink, name, actual, counter)
			continue
		}

		t.Cleanup(func() { counter.Store(0) })
		value := uint64(vulnerabilityType)*41 + 1
		counter.Store(value)
		expected[vulnerabilityType] = value
	}

	for vulnerabilityType, counter := range telemetry.ExecutedSink.Each {
		if got, want := counter.Load(), expected[vulnerabilityType]; got != want {
			t.Errorf("counter for %s = %d, want %d", vulnerabilityType, got, want)
		}
		delete(expected, vulnerabilityType)
	}
	if len(expected) != 0 {
		t.Errorf("vulnerability types not visited by Each: %v", expected)
	}
}

func captureSourceOrder() []constants.Origin {
	var order []constants.Origin
	for origin := range telemetry.ExecutedSource.Each {
		order = append(order, origin)
	}
	return order
}

func captureSinkOrder() []constants.VulnerabilityType {
	var order []constants.VulnerabilityType
	for vulnerabilityType := range telemetry.ExecutedSink.Each {
		order = append(order, vulnerabilityType)
	}
	return order
}

func TestExecutedSourceEachVisitsExactlyAllOrigins(t *testing.T) {
	order := captureSourceOrder()
	all := constants.AllOrigins()
	if got, want := len(order), len(all); got != want {
		t.Errorf("iteration count = %d, want %d", got, want)
	}

	seen := make(map[constants.Origin]bool, len(order))
	for _, origin := range order {
		if seen[origin] {
			t.Errorf("origin %s was visited more than once", origin)
		}
		seen[origin] = true
	}
	for name, origin := range all {
		if !seen[origin] {
			t.Errorf("origin %s (%s) was not visited", name, origin)
		}
	}
}

func TestExecutedSinkEachVisitsExactlyAllVulnerabilityTypes(t *testing.T) {
	order := captureSinkOrder()
	all := constants.AllVulnerabilityTypes()
	if got, want := len(order), len(all); got != want {
		t.Errorf("iteration count = %d, want %d", got, want)
	}

	seen := make(map[constants.VulnerabilityType]bool, len(order))
	for _, vulnerabilityType := range order {
		if seen[vulnerabilityType] {
			t.Errorf("vulnerability type %s was visited more than once", vulnerabilityType)
		}
		seen[vulnerabilityType] = true
	}
	for name, vulnerabilityType := range all {
		if !seen[vulnerabilityType] {
			t.Errorf("vulnerability type %s (%s) was not visited", name, vulnerabilityType)
		}
	}
}

func TestExecutedSourceEachRangeBreaksAtEveryPoint(t *testing.T) {
	order := captureSourceOrder()
	if len(order) == 0 {
		t.Fatal("ExecutedSource.Each produced no values")
	}

	for i := range order {
		t.Run(fmt.Sprintf("break_at_%d_%s", i, order[i]), func(t *testing.T) {
			var visited []constants.Origin
			for origin := range telemetry.ExecutedSource.Each {
				visited = append(visited, origin)
				if origin == order[i] {
					break
				}
			}
			if want := order[:i+1]; !reflect.DeepEqual(visited, want) {
				t.Errorf("visited = %v, want %v", visited, want)
			}
		})
	}
}

func TestExecutedSinkEachRangeBreaksAtEveryPoint(t *testing.T) {
	order := captureSinkOrder()
	if len(order) == 0 {
		t.Fatal("ExecutedSink.Each produced no values")
	}

	for i := range order {
		t.Run(fmt.Sprintf("break_at_%d_%s", i, order[i]), func(t *testing.T) {
			var visited []constants.VulnerabilityType
			for vulnerabilityType := range telemetry.ExecutedSink.Each {
				visited = append(visited, vulnerabilityType)
				if vulnerabilityType == order[i] {
					break
				}
			}
			if want := order[:i+1]; !reflect.DeepEqual(visited, want) {
				t.Errorf("visited = %v, want %v", visited, want)
			}
		})
	}
}

func TestExecutedSourceEachCallbackStopsOnFalse(t *testing.T) {
	order := captureSourceOrder()
	if len(order) == 0 {
		t.Fatal("ExecutedSource.Each produced no values")
	}
	stopAfter := len(order)/2 + 1

	var visited []constants.Origin
	telemetry.ExecutedSource.Each(func(origin constants.Origin, _ *atomic.Uint64) bool {
		visited = append(visited, origin)
		return len(visited) < stopAfter
	})
	if want := order[:stopAfter]; !reflect.DeepEqual(visited, want) {
		t.Errorf("visited = %v, want %v", visited, want)
	}
}

func TestExecutedSinkEachCallbackStopsOnFalse(t *testing.T) {
	order := captureSinkOrder()
	if len(order) == 0 {
		t.Fatal("ExecutedSink.Each produced no values")
	}
	stopAfter := len(order)/2 + 1

	var visited []constants.VulnerabilityType
	telemetry.ExecutedSink.Each(func(vulnerabilityType constants.VulnerabilityType, _ *atomic.Uint64) bool {
		visited = append(visited, vulnerabilityType)
		return len(visited) < stopAfter
	})
	if want := order[:stopAfter]; !reflect.DeepEqual(visited, want) {
		t.Errorf("visited = %v, want %v", visited, want)
	}
}
