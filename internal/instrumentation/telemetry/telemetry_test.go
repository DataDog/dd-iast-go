package telemetry

import (
	"math/rand/v2"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaxCardinalities(t *testing.T) {
	require.LessOrEqual(t, len(constants.AllOrigins()), maxCardinalitySources, "the count of Origins is over maxCardinalitySources")
	require.LessOrEqual(t, len(constants.AllVulnerabilityTypes()), maxCardinalitySinks, "the count of VulnerabilityTypes is over maxCardinalitySinks")
}

func TestExecutedSource(t *testing.T) {
	origins := constants.AllOrigins()
	subject := &executedSource{}

	expected := make(map[constants.Origin]uint64, len(origins))

	rv := reflect.ValueOf(subject).Elem()
	for name, origin := range origins {
		field := rv.FieldByName(name)
		assert.True(t, field.IsValid(), "missing field: %T.%s", subject, name)
		ctr, ok := field.Addr().Interface().(*atomic.Uint64)
		assert.True(t, ok, "field %T.%s is not %T", subject, name, ctr)

		val := rand.Uint64()
		ctr.Store(val)
		expected[origin] = val
	}

	for origin, ctr := range subject.Each {
		assert.Equal(t, ctr.Load(), expected[origin])
	}
}

func TestExecutedSink(t *testing.T) {
	vulnTypes := constants.AllVulnerabilityTypes()
	subject := &executedSink{}

	expected := make(map[constants.VulnerabilityType]uint64, len(vulnTypes))

	rv := reflect.ValueOf(subject).Elem()
	for name, vulnType := range vulnTypes {
		field := rv.FieldByName(name)
		assert.True(t, field.IsValid(), "missing field: %T.%s", subject, name)
		ctr, ok := field.Addr().Interface().(*atomic.Uint64)
		assert.True(t, ok, "field %T.%s is not %T", subject, name, ctr)

		val := rand.Uint64()
		ctr.Store(val)
		expected[vulnType] = val
	}

	for vulnType, ctr := range subject.Each {
		assert.Equal(t, ctr.Load(), expected[vulnType])
	}
}
