// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp

// BuildSharedQuery concatenates a value of the current request and a value of
// a different request into one new allocation. Both request owners adopt this
// allocation, each with its own ranges.
func BuildSharedQuery(own, foreign string) string {
	return "SELECT '" + own + "', '" + foreign + "'"
}

// BuildForeignQuery builds a query that contains only a value of a different
// request.
func BuildForeignQuery(foreign string) string {
	return "SELECT '" + foreign + "'"
}
