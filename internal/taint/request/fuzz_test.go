// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request_test

import (
	"fmt"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/stretchr/testify/require"
)

// FuzzAdd exercises the table with arbitrary origin/name/value inputs. It
// asserts no panic, stable IDs (re-adding the same source returns the same
// result), exact dedup, and capacity never exceeding MaxSources.
func FuzzAdd(f *testing.F) {
	f.Add(uint8(constants.OriginHttpRequestParameter), "name", "value")
	f.Add(uint8(0), "", "")
	f.Add(uint8(200), "x", "y")
	f.Add(uint8(constants.OriginHttpRequestBody), "h", "v")
	f.Add(uint8(constants.OriginSqlRowValue), "", "long-value-with-ünicode-∂µ")
	f.Fuzz(func(t *testing.T, ob uint8, name, value string) {
		origin := constants.Origin(ob)
		tab := request.New()

		r1 := tab.Add(origin, name, value)
		r2 := tab.Add(origin, name, value)
		require.Equal(t, r1.ID, r2.ID, "re-adding the same source must return a stable ID")

		if !(ob != 0 && uint(ob) <= uint(constants.OriginCount)) {
			require.Equal(t, request.AddRejected, r1.Status)
			require.Equal(t, 0, tab.Len())
			return
		}

		// Fresh table: first add is new (ID 0), second is a duplicate.
		require.Equal(t, request.AddAdded, r1.Status)
		require.Equal(t, request.AddDuplicate, r2.Status)
		require.Equal(t, request.SourceID(0), r1.ID)
		require.Equal(t, r1.ID, r2.ID)

		// Push toward capacity with distinct derived sources.
		for i := 0; i < 300; i++ {
			n := fmt.Sprintf("n%d", i)
			v := fmt.Sprintf("v%d|%s|%s", i, name, value)
			tab.Add(constants.OriginHttpRequestParameter, n, v)
			require.LessOrEqual(t, tab.Len(), request.MaxSources, "capacity must never be exceeded")
		}

		// The original source (ID 0) is never evicted; re-adding it is a duplicate.
		r3 := tab.Add(origin, name, value)
		require.Equal(t, request.AddDuplicate, r3.Status)
		require.Equal(t, request.SourceID(0), r3.ID)
		require.LessOrEqual(t, tab.Len(), request.MaxSources)
	})
}
