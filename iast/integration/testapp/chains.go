// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp

import (
	"fmt"
	"strings"
)

// SQLChainValues exposes each application transform for provenance inspection.
type SQLChainValues struct {
	Column string
	Table  string
	Joined string
	Query  string
}

// BuildSQLChain builds a query through exact transforms and coarse formatting.
// The column input must contain at least two bytes.
// Native calls live here because the pinned injector's root filter excludes
// an external test package at the module root.
func BuildSQLChain(column, table string) SQLChainValues {
	result := SQLChainValues{
		Column: column[:2],
		Table:  strings.TrimSpace(table),
	}
	result.Joined = strings.Join([]string{"SELECT ", result.Column, " FROM ", result.Table}, "")
	result.Query = fmt.Sprintf("%s", result.Joined)
	return result
}
