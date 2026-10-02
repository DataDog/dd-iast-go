// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package ranges

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/stretchr/testify/require"
)

func TestOrderedBuilderInvalidPublishDropsResult(t *testing.T) {
	var builder orderedBuilder
	builder.init(DefaultLimit)
	builder.append(Range{Start: 2, Length: 1})
	builder.append(Range{Start: 0, Length: 1})

	var dst Set
	dst.items[0] = Range{Length: 1}
	dst.count = 1
	outcome := builder.publish(&dst)
	require.False(t, outcome.Valid)
	require.Zero(t, dst.Len())
}

func TestMarksRejectStructurallyInvalidSet(t *testing.T) {
	invalid := Set{limit: 1, count: 2}
	invalid.items[0] = Range{Length: 1}
	invalid.items[1] = Range{Start: 2, Length: 1}

	var dst Set
	outcome := MarkAll(&dst, &invalid, constants.VulnerabilityTypeSqlInjection)
	require.False(t, outcome.Valid)
	require.Zero(t, dst.Len())

	outcome = UnsafeFor(&dst, &invalid, constants.VulnerabilityTypeSqlInjection)
	require.False(t, outcome.Valid)
	require.Zero(t, dst.Len())
}
