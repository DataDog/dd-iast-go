package telemetry_test

import (
	"math/rand/v2"
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
		assert.True(t, field.IsValid(), "missing field: %T.%s", &telemetry.ExecutedSource, name)
		ctr, ok := field.Addr().Interface().(*atomic.Uint64)
		assert.True(t, ok, "field %T.%s is not %T", &telemetry.ExecutedSource, name, ctr)

		val := rand.Uint64()
		ctr.Store(val)
		expected[origin] = val
	}

	for origin, ctr := range telemetry.ExecutedSource.Each {
		assert.Equal(t, ctr.Load(), expected[origin])
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
		assert.True(t, field.IsValid(), "missing field: %T.%s", &telemetry.ExecutedSink, name)
		ctr, ok := field.Addr().Interface().(*atomic.Uint64)
		assert.True(t, ok, "field %T.%s is not %T", &telemetry.ExecutedSink, name, ctr)

		val := rand.Uint64()
		ctr.Store(val)
		expected[vulnType] = val
	}

	for vulnType, ctr := range telemetry.ExecutedSink.Each {
		assert.Equal(t, ctr.Load(), expected[vulnType])
		delete(expected, vulnType)
	}
	assert.Empty(t, expected, "some vulnerability types were not visited by Each: %v", expected)
}
