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
	"unsafe"
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
	// The callback check comes first: when IAST is disabled, the headers are
	// not read.
	callback := registered.Load()
	if callback == nil {
		return ctx, false
	}
	if method == "PRI" && requestURI == "*" || isH2CUpgrade(headers) {
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

// MaxBodyTypes is the number of body types that [RegisterBodyType] can
// register.
const MaxBodyTypes = 4

// bodyTypes are the type words of the registered body types (see
// RegisterBodyType). A nil entry is free. The type words are static data of
// the binary: they are never freed.
var bodyTypes [MaxBodyTypes]atomic.Pointer[byte]

// eface is the layout of an empty interface value.
type eface struct {
	typ  *byte
	data unsafe.Pointer
}

// RegisterBodyType registers the dynamic type of object as the type of a
// request body whose Read method has a taint hook. object must be a nil
// pointer of that type, for example (*body)(nil). The hooked packages call
// it in the initialization of a package variable. It returns false when
// object is nil, or when all the entries are used.
func RegisterBodyType(object any) bool {
	typ := (*eface)(unsafe.Pointer(&object)).typ
	if typ == nil {
		return false
	}
	for i := range bodyTypes {
		if bodyTypes[i].Load() == typ || bodyTypes[i].CompareAndSwap(nil, typ) {
			return true
		}
	}
	return false
}

// BodyObject returns the data pointer of object when its dynamic type is a
// registered body type (see [RegisterBodyType]), else nil. The registered
// types are pointer types of the standard library (and of
// golang.org/x/net), whose objects the servers allocate on the heap. Thus
// the result is always nil or a heap pointer, which is safe for weak.Make.
func BodyObject(object any) unsafe.Pointer {
	e := (*eface)(unsafe.Pointer(&object))
	if e.typ == nil || e.data == nil {
		return nil
	}
	for i := range bodyTypes {
		typ := bodyTypes[i].Load()
		if typ == nil {
			return nil
		}
		if typ == e.typ {
			return e.data
		}
	}
	return nil
}

func isH2CUpgrade(headers map[string][]string) bool {
	if !headerHasToken(headers["Upgrade"], "h2c") || !headerHasToken(headers["Connection"], "upgrade") || !headerHasToken(headers["Connection"], "http2-settings") {
		return false
	}
	size := 0
	for i, value := range headers["Http2-Settings"] {
		// The same bounds as headerHasToken: a real HTTP2-Settings header is
		// one short value.
		if size += len(value); size > maxHeaderBytes || i >= maxHeaderTokens {
			return false
		}
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

// maxHeaderBytes and maxHeaderTokens bound the work of headerHasToken for
// one header name. The header values come from the client, so an unbounded
// scan would let a request with a very long header add CPU work to every
// request. A real h2c upgrade request has short Upgrade and Connection
// headers.
const (
	maxHeaderBytes  = 256
	maxHeaderTokens = 32
)

// headerHasToken reports whether values contain want as a comma-separated
// token. When the header is longer than maxHeaderBytes or has more than
// maxHeaderTokens tokens, it stops and reports false: such a request is not
// a real h2c upgrade, and it is analyzed normally (as in PR #39), with
// bounded work.
func headerHasToken(values []string, want string) bool {
	size, tokens := 0, 0
	for _, value := range values {
		if size += len(value); size > maxHeaderBytes {
			return false
		}
		for token := range strings.SplitSeq(value, ",") {
			if tokens++; tokens > maxHeaderTokens {
				return false
			}
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}
