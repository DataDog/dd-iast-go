// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request_test

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/stretchr/testify/require"
)

// validOrigin mirrors the production validity rule for use in tests.
func validOrigin(o constants.Origin) bool {
	return o != 0 && uint(o) <= uint(constants.OriginCount)
}

func TestZeroValueTableIsUsable(t *testing.T) {
	var tab request.Table
	res := tab.Add(constants.OriginHttpRequestParameter, "q", "v")
	require.Equal(t, request.AddAdded, res.Status)
	require.Equal(t, request.SourceID(0), res.ID)
	require.Equal(t, 1, tab.Len())
}

func TestIDZeroIsValid(t *testing.T) {
	tab := request.New()
	res := tab.Add(constants.OriginHttpRequestParameter, "q", "v")
	require.Equal(t, request.AddAdded, res.Status)
	require.Equal(t, request.SourceID(0), res.ID, "first source must get ID 0")

	got, ok := tab.Get(0)
	require.True(t, ok, "Get(0) must succeed after an add")
	require.Equal(t, constants.OriginHttpRequestParameter, got.Origin)
	require.Equal(t, "q", got.Name)
	require.Equal(t, "v", got.Value)
}

func TestExactDuplicate(t *testing.T) {
	tab := request.New()
	r1 := tab.Add(constants.OriginHttpRequestHeader, "h", "v")
	r2 := tab.Add(constants.OriginHttpRequestHeader, "h", "v")
	require.Equal(t, request.AddAdded, r1.Status)
	require.Equal(t, request.AddDuplicate, r2.Status)
	require.Equal(t, r1.ID, r2.ID, "duplicate must return the existing ID")
	require.Equal(t, 1, tab.Len())
}

func TestDifferingEqualityFields(t *testing.T) {
	tab := request.New()
	base := tab.Add(constants.OriginHttpRequestParameter, "n", "v")
	require.Equal(t, request.AddAdded, base.Status)

	// Differ by origin.
	r := tab.Add(constants.OriginHttpRequestHeader, "n", "v")
	require.Equal(t, request.AddAdded, r.Status)
	require.NotEqual(t, base.ID, r.ID)

	// Differ by name.
	r = tab.Add(constants.OriginHttpRequestParameter, "n2", "v")
	require.Equal(t, request.AddAdded, r.Status)
	require.NotEqual(t, base.ID, r.ID)

	// Differ by value.
	r = tab.Add(constants.OriginHttpRequestParameter, "n", "v2")
	require.Equal(t, request.AddAdded, r.Status)
	require.NotEqual(t, base.ID, r.ID)

	require.Equal(t, 4, tab.Len())
}

func TestFill256(t *testing.T) {
	tab := request.New()
	for i := 0; i < request.MaxSources; i++ {
		res := tab.Add(constants.OriginHttpRequestParameter, "n", fmt.Sprintf("v%d", i))
		require.Equal(t, request.AddAdded, res.Status, "add %d should be new", i)
		require.Equal(t, request.SourceID(i), res.ID)
	}
	require.Equal(t, request.MaxSources, tab.Len())
}

func TestDuplicateWhenFull(t *testing.T) {
	tab := request.New()
	for i := 0; i < request.MaxSources; i++ {
		tab.Add(constants.OriginHttpRequestParameter, "n", fmt.Sprintf("v%d", i))
	}
	require.Equal(t, request.MaxSources, tab.Len())

	// Re-add an existing source: must return its existing ID, not a capacity drop.
	res := tab.Add(constants.OriginHttpRequestParameter, "n", "v42")
	require.Equal(t, request.AddDuplicate, res.Status)
	require.Equal(t, request.SourceID(42), res.ID)
	require.Equal(t, request.MaxSources, tab.Len(), "duplicate at capacity must not grow the table")
}

func TestNewValueWhenFull(t *testing.T) {
	tab := request.New()
	for i := 0; i < request.MaxSources; i++ {
		tab.Add(constants.OriginHttpRequestParameter, "n", fmt.Sprintf("v%d", i))
	}
	before := snapshot(t, tab)
	res := tab.Add(constants.OriginHttpRequestParameter, "n", "never-seen-before")
	require.Equal(t, request.AddFull, res.Status)
	require.Equal(t, request.MaxSources, tab.Len())
	require.Equal(t, before, snapshot(t, tab), "capacity rejection must change nothing")
}

func TestInvalidOrigins(t *testing.T) {
	tab := request.New()
	for _, o := range []constants.Origin{0, constants.Origin(constants.OriginCount + 1), 255} {
		res := tab.Add(o, "n", "v")
		require.Equalf(t, request.AddRejected, res.Status, "origin %d must be rejected", o)
	}
	require.Equal(t, 0, tab.Len(), "rejected adds must not be stored")
}

func TestGetBounds(t *testing.T) {
	tab := request.New()
	tab.Add(constants.OriginHttpRequestParameter, "a", "1")
	tab.Add(constants.OriginHttpRequestParameter, "b", "2")
	require.Equal(t, 2, tab.Len())

	_, ok := tab.Get(0)
	require.True(t, ok)
	_, ok = tab.Get(1)
	require.True(t, ok)
	_, ok = tab.Get(2)
	require.False(t, ok, "Get at count must be out of range")
	_, ok = tab.Get(request.SourceID(request.MaxSources))
	require.False(t, ok)
	_, ok = tab.Get(request.SourceID(65535))
	require.False(t, ok)
}

func TestResetReleasesAndRestartsIDs(t *testing.T) {
	tab := request.New()
	for i := 0; i < 16; i++ {
		tab.Add(constants.OriginHttpRequestParameter, "n", fmt.Sprintf("v%d", i))
	}
	require.Equal(t, 16, tab.Len())
	tab.Reset()
	require.Equal(t, 0, tab.Len())
	_, ok := tab.Get(0)
	require.False(t, ok, "Reset must release all entries")

	// IDs restart from 0 after Reset.
	res := tab.Add(constants.OriginHttpRequestHeader, "h", "v")
	require.Equal(t, request.AddAdded, res.Status)
	require.Equal(t, request.SourceID(0), res.ID)
}

func TestNilReceiverSafety(t *testing.T) {
	var tab *request.Table // nil

	res := tab.Add(constants.OriginHttpRequestParameter, "n", "v")
	require.Equal(t, request.AddRejected, res.Status)

	_, ok := tab.Get(0)
	require.False(t, ok)

	require.Equal(t, 0, tab.Len())

	require.NotPanics(t, func() { tab.Reset() })
}

func TestPropertyDedup(t *testing.T) {
	r := rand.New(rand.NewPCG(0xC0FFEE, 0xBEEF))
	tab := request.New()
	oracle := make(map[oracleKey]request.SourceID)

	namePool := []string{"", "q", "id", "name", "header", "cookie", "path"}
	valuePool := []string{"", "1", "value", "<script>", "a;b", "x=y", "p/q"}
	validOrigins := []constants.Origin{
		constants.OriginHttpRequestParameter,
		constants.OriginHttpRequestHeader,
		constants.OriginHttpRequestPath,
		constants.OriginHttpRequestBody,
		constants.OriginHttpRequestQuery,
		constants.OriginHttpRequestCookieValue,
	}

	for i := 0; i < 20000; i++ {
		// Inject an invalid origin ~5% of the time.
		var origin constants.Origin
		if r.IntN(20) == 0 {
			origin = constants.Origin(r.IntN(256)) // likely invalid
		} else {
			origin = validOrigins[r.IntN(len(validOrigins))]
		}
		name := namePool[r.IntN(len(namePool))]
		value := valuePool[r.IntN(len(valuePool))]

		res := tab.Add(origin, name, value)
		key := oracleKey{origin, name, value}

		switch {
		case !validOrigin(origin):
			require.Equal(t, request.AddRejected, res.Status)
		default:
			existing, ok := oracle[key]
			switch {
			case ok:
				require.Equal(t, request.AddDuplicate, res.Status)
				require.Equal(t, existing, res.ID, "duplicate must return the stable existing ID")
			case len(oracle) >= request.MaxSources:
				require.Equal(t, request.AddFull, res.Status)
			default:
				require.Equal(t, request.AddAdded, res.Status)
				expectedID := request.SourceID(len(oracle))
				require.Equal(t, expectedID, res.ID, "new source must get the next sequential ID")
				oracle[key] = res.ID
			}
		}

		require.LessOrEqual(t, tab.Len(), request.MaxSources, "capacity must never be exceeded")
		require.Equal(t, len(oracle), tab.Len(), "table length must match the oracle")
	}
}

func TestAddDuplicateNoAlloc(t *testing.T) {
	tab := request.New()
	tab.Add(constants.OriginHttpRequestParameter, "k", "v")
	allocs := testing.AllocsPerRun(100, func() {
		tab.Add(constants.OriginHttpRequestParameter, "k", "v")
	})
	require.Equal(t, float64(0), allocs, "duplicate lookup must not allocate")
}

func TestAddFullNoAlloc(t *testing.T) {
	tab := request.New()
	for i := 0; i < request.MaxSources; i++ {
		tab.Add(constants.OriginHttpRequestParameter, "n", fmt.Sprintf("v%d", i))
	}
	allocs := testing.AllocsPerRun(100, func() {
		tab.Add(constants.OriginHttpRequestParameter, "n", "not-present")
	})
	require.Equal(t, float64(0), allocs, "capacity rejection must not allocate")
}

type oracleKey struct {
	origin constants.Origin
	name   string
	value  string
}

// snapshot captures the full table contents for change-detection tests.
func snapshot(t *testing.T, tab *request.Table) map[request.SourceID]request.Source {
	t.Helper()
	out := make(map[request.SourceID]request.Source, tab.Len())
	for i := 0; i < tab.Len(); i++ {
		s, ok := tab.Get(request.SourceID(i))
		require.True(t, ok)
		out[request.SourceID(i)] = s
	}
	return out
}
