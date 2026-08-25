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

type lazyCallbacks struct {
	form               func(context.Context, map[string][]string, map[string][]string) (map[string][]string, map[string][]string)
	parameter          func(context.Context, string, string) string
	multipartParameter func(context.Context, string, string) string
	path               func(context.Context, string, string) string
	cookie             func(context.Context, *string, *string)
	multipart          func(context.Context, map[string][]string, map[string][]string, map[string][]string) map[string][]string
}

var (
	registered     atomic.Pointer[callbacks]
	registeredLazy atomic.Pointer[lazyCallbacks]
)

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

// RegisterLazy installs lazy request-source callbacks during package
// initialization.
func RegisterLazy(
	form func(context.Context, map[string][]string, map[string][]string) (map[string][]string, map[string][]string),
	parameter func(context.Context, string, string) string,
	multipartParameter func(context.Context, string, string) string,
	path func(context.Context, string, string) string,
	cookie func(context.Context, *string, *string),
	multipart func(context.Context, map[string][]string, map[string][]string, map[string][]string) map[string][]string,
) {
	if form == nil || parameter == nil || multipartParameter == nil || path == nil || cookie == nil || multipart == nil {
		return
	}
	registeredLazy.Store(&lazyCallbacks{
		form: form, parameter: parameter, multipartParameter: multipartParameter,
		path: path, cookie: cookie, multipart: multipart,
	})
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

// Form manages parsed request form maps.
func Form(ctx context.Context, form, postForm map[string][]string) (map[string][]string, map[string][]string) {
	callback := registeredLazy.Load()
	if callback == nil {
		return form, postForm
	}
	return callback.form(ctx, form, postForm)
}

// Parameter manages one lazily returned parameter value.
func Parameter(ctx context.Context, name, value string) string {
	callback := registeredLazy.Load()
	if callback == nil {
		return value
	}
	return callback.parameter(ctx, name, value)
}

// MultipartParameter manages one lazily returned multipart value.
func MultipartParameter(ctx context.Context, name, value string) string {
	callback := registeredLazy.Load()
	if callback == nil {
		return value
	}
	return callback.multipartParameter(ctx, name, value)
}

// PathParameter manages one lazily returned path parameter value.
func PathParameter(ctx context.Context, name, value string) string {
	callback := registeredLazy.Load()
	if callback == nil {
		return value
	}
	return callback.path(ctx, name, value)
}

// Cookie manages one cookie name and value in place.
func Cookie(ctx context.Context, name, value *string) {
	callback := registeredLazy.Load()
	if callback != nil {
		callback.cookie(ctx, name, value)
	}
}

// Multipart manages parsed multipart value parts and their combined-form
// suffixes. File parts are not source values.
func Multipart(ctx context.Context, values, form, postForm map[string][]string) map[string][]string {
	callback := registeredLazy.Load()
	if callback == nil {
		return values
	}
	return callback.multipart(ctx, values, form, postForm)
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
