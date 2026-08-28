// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package operatorbridge

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHasValues(t *testing.T) {
	values := ActiveValues()
	values.Store(0)
	require.False(t, HasValues())
	values.Store(1)
	require.True(t, HasValues())
	values.Store(0)
}

func BenchmarkHasValuesClean(b *testing.B) {
	ActiveValues().Store(0)
	b.ReportAllocs()
	for b.Loop() {
		_ = HasValues()
	}
}
