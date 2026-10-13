// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package httpbridge_test

import (
	"context"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/httpbridge"
	"github.com/stretchr/testify/require"
)

func TestBeginSkipsH2CConnectionRequests(t *testing.T) {
	calls := 0
	httpbridge.Register(
		func(ctx context.Context) (context.Context, bool) {
			calls++
			return ctx, true
		},
		func(context.Context, bool) {},
		func(_ context.Context, _, _, _ *string, headers map[string][]string, _, _ any) map[string][]string {
			return headers
		},
	)
	ctx := context.Background()

	_, created := httpbridge.Begin(ctx, "PRI", "*", nil)
	require.False(t, created)
	headers := map[string][]string{
		"Upgrade":        {"H2C"},
		"Connection":     {"keep-alive, Upgrade, HTTP2-Settings"},
		"Http2-Settings": {"AAMAAABkAAQAAP__"},
	}
	_, created = httpbridge.Begin(ctx, "GET", "/", headers)
	require.False(t, created)
	require.Zero(t, calls)

	_, created = httpbridge.Begin(ctx, "GET", "/", nil)
	require.True(t, created)
	require.Equal(t, 1, calls)
}

// TestBeginBoundsHeaderTokenScan: a header with many tokens or many bytes
// stops the scan after a fixed amount of work, and the request is analyzed
// normally (it is not a real h2c upgrade). A short h2c upgrade is still
// skipped.
func TestBeginBoundsHeaderTokenScan(t *testing.T) {
	calls := 0
	httpbridge.Register(
		func(ctx context.Context) (context.Context, bool) {
			calls++
			return ctx, true
		},
		func(context.Context, bool) {},
		func(_ context.Context, _, _, _ *string, headers map[string][]string, _, _ any) map[string][]string {
			return headers
		},
	)
	ctx := context.Background()
	for name, long := range map[string]string{
		"tokens": strings.Repeat("x,", 33) + "h2c, upgrade, http2-settings",
		"bytes":  strings.Repeat(" ", 1<<20) + "h2c, upgrade, http2-settings",
	} {
		t.Run(name, func(t *testing.T) {
			headers := map[string][]string{
				"Upgrade":        {long},
				"Connection":     {long},
				"Http2-Settings": {"AAMAAABkAAQAAP__"},
			}
			before := calls
			_, created := httpbridge.Begin(ctx, "GET", "/", headers)
			require.True(t, created, "an oversized header is not an h2c upgrade")
			require.Equal(t, before+1, calls)
			require.Zero(t, testing.AllocsPerRun(10, func() {
				_, _ = httpbridge.Begin(ctx, "GET", "/", headers)
			}))
		})
	}

	// An oversized HTTP2-Settings header: not an h2c upgrade, bounded work.
	settings := map[string][]string{
		"Upgrade":        {"h2c"},
		"Connection":     {"Upgrade, HTTP2-Settings"},
		"Http2-Settings": {strings.Repeat(" ", 1<<20)},
	}
	before0 := calls
	_, created0 := httpbridge.Begin(ctx, "GET", "/", settings)
	require.True(t, created0)
	require.Equal(t, before0+1, calls)

	// Many empty HTTP2-Settings values: bounded by the value count.
	empties := map[string][]string{
		"Upgrade":        {"h2c"},
		"Connection":     {"Upgrade, HTTP2-Settings"},
		"Http2-Settings": append(make([]string, 100000), "AAMAAABkAAQAAP__"),
	}
	before1 := calls
	_, created1 := httpbridge.Begin(ctx, "GET", "/", empties)
	require.True(t, created1)
	require.Equal(t, before1+1, calls)

	short := map[string][]string{
		"Upgrade":        {"h2c"},
		"Connection":     {"Upgrade, HTTP2-Settings"},
		"Http2-Settings": {"AAMAAABkAAQAAP__"},
	}
	before := calls
	_, created := httpbridge.Begin(ctx, "GET", "/", short)
	require.False(t, created)
	require.Equal(t, before, calls)
}

func TestRegisterRejectsIncompletePair(t *testing.T) {
	require.NotPanics(t, func() {
		eager := func(_ context.Context, _, _, _ *string, headers map[string][]string, _, _ any) map[string][]string {
			return headers
		}
		httpbridge.Register(nil, func(context.Context, bool) {}, eager)
		httpbridge.Register(func(ctx context.Context) (context.Context, bool) {
			return ctx, true
		}, nil, eager)
	})
}

type registeredBody struct{ n int }

type otherBody struct{ n int }

func TestBodyObjectNeedsARegisteredType(t *testing.T) {
	require.False(t, httpbridge.RegisterBodyType(nil))
	require.True(t, httpbridge.RegisterBodyType((*registeredBody)(nil)))
	// A second registration of the same type uses the same entry.
	require.True(t, httpbridge.RegisterBodyType((*registeredBody)(nil)))

	body := &registeredBody{n: 1}
	require.Equal(t, unsafe.Pointer(body), httpbridge.BodyObject(body))
	require.Nil(t, httpbridge.BodyObject(&otherBody{n: 2}), "a type that is not registered")
	require.Nil(t, httpbridge.BodyObject((*registeredBody)(nil)), "a nil pointer")
	require.Nil(t, httpbridge.BodyObject(nil))
	require.Nil(t, httpbridge.BodyObject(registeredBody{n: 3}), "a value of the element type")
}
