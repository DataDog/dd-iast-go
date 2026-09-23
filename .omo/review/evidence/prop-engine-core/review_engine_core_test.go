// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestReviewCleanDerivedWindowDoesNotCloneCoarseOutput(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	root, _ := taintString(t, owner, "xxa b", []ranges.Range{{Length: 2, SourceID: 1}})
	clean := root[2:]
	propagation.StringWindow(root, clean)
	require.Empty(t, lookupRanges(s, clean))
	native := strings.ReplaceAll(clean, " ", "+")

	result := propagation.CoarseString(native, clean)

	require.True(t, unsafe.StringData(result) == unsafe.StringData(native),
		"clean input should not cause a redundant clone")
}

func TestReviewEmptyTailWindowsDoNotCountDroppedContributions(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	root, _ := taintString(t, owner, "attacker", []ranges.Range{{Length: 8, SourceID: 1}})
	outputs := make([]string, 33)
	outputs[0] = root[:2]
	telemetry.DroppedPropagation.Store(0)

	propagation.StringWindows(root, outputs)

	require.Zero(t, telemetry.DroppedPropagation.Load(),
		"empty bounded-out outputs have no provenance to drop")
}
