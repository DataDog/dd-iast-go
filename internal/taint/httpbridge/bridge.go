// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package httpbridge is the dependency-minimal bridge imported into net/http.
package httpbridge

import (
	"context"
	"strings"
	"sync/atomic"
)

type callbacks struct {
	begin  func(context.Context) (context.Context, bool)
	finish func(context.Context, bool)
	eager  func(context.Context, *string, *string, *string, map[string][]string, any, any) map[string][]string
}

var registered atomic.Pointer[callbacks]

// Register installs the process callbacks. It is intended for package
// initialization; the latest complete callback pair wins.
func Register(
	begin func(context.Context) (context.Context, bool),
	finish func(context.Context, bool),
	eager func(context.Context, *string, *string, *string, map[string][]string, any, any) map[string][]string,
) {
	if begin == nil || finish == nil || eager == nil {
		return
	}
	registered.Store(&callbacks{begin: begin, finish: finish, eager: eager})
}

// Begin starts a server request scope unless this is a connection-level h2c
// preface or upgrade. A missing callback is a disabled no-op.
func Begin(ctx context.Context, method, requestURI string, headers map[string][]string) (context.Context, bool) {
	if method == "PRI" && requestURI == "*" || isH2CUpgrade(headers) {
		return ctx, false
	}
	callback := registered.Load()
	if callback == nil {
		return ctx, false
	}
	return callback.begin(ctx)
}

// Eager registers request fields and object relationships without parsing or
// reading the request. A missing callback returns headers unchanged.
func Eager(
	ctx context.Context,
	requestURI, path, rawQuery *string,
	headers map[string][]string,
	urlObject, bodyObject any,
) map[string][]string {
	callback := registered.Load()
	if callback == nil {
		return headers
	}
	return callback.eager(ctx, requestURI, path, rawQuery, headers, urlObject, bodyObject)
}

// Finish releases a scope created by Begin. A missing callback is a no-op.
func Finish(ctx context.Context, created bool) {
	callback := registered.Load()
	if callback == nil {
		return
	}
	callback.finish(ctx, created)
}

func isH2CUpgrade(headers map[string][]string) bool {
	if !headerHasToken(headers["Upgrade"], "h2c") || !headerHasToken(headers["Connection"], "upgrade") || !headerHasToken(headers["Connection"], "http2-settings") {
		return false
	}
	for _, value := range headers["Http2-Settings"] {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func headerHasToken(values []string, want string) bool {
	for _, value := range values {
		for token := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}
