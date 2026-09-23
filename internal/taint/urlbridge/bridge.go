// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package urlbridge is the dependency-minimal bridge imported into net/url.
package urlbridge

import "sync/atomic"

type callbackHolder struct {
	query func(any, map[string][]string) map[string][]string
}

var registered atomic.Pointer[callbackHolder]

// Register installs the URL query callback during package initialization.
func Register(query func(any, map[string][]string) map[string][]string) {
	if query != nil {
		registered.Store(&callbackHolder{query: query})
	}
}

// Query manages one parsed query result for a bound URL object.
func Query(urlObject any, values map[string][]string) map[string][]string {
	callback := registered.Load()
	if callback == nil {
		return values
	}
	return callback.query(urlObject, values)
}
