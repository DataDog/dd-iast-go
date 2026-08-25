// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package httpbridge_test

import (
	"context"
	"testing"

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

func TestRegisterRejectsIncompletePair(t *testing.T) {
	require.NotPanics(t, func() {
		httpbridge.Register(nil, func(context.Context, bool) {})
		httpbridge.Register(func(ctx context.Context) (context.Context, bool) {
			return ctx, true
		}, nil)
	})
}
