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

// BuildSQLChain builds a query through a slice, strings.TrimSpace,
// strings.Join and fmt.Sprintf. Each of these copies the taint bits exactly.
// The column input must contain at least two bytes.
func BuildSQLChain(column, table string) SQLChainValues {
	result := SQLChainValues{
		Column: column[:2],
		Table:  strings.TrimSpace(table),
	}
	result.Joined = strings.Join([]string{"SELECT ", result.Column, " FROM ", result.Table}, "")
	result.Query = fmt.Sprintf("%s", result.Joined)
	return result
}

// BuildQuoteQuery puts quote between 2 literal quotes. The runtime concat
// hook copies the taint bits of quote into the new string.
func BuildQuoteQuery(quote string) string {
	return "SELECT '" + quote + "';"
}
