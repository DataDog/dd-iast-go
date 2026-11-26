// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapranges

import "testing"

func TestOwnerFunctionsWhenNotWoven(t *testing.T) {
	if runtimeStartOwner != nil || runtimeEndOwner != nil || runtimeOwnerLive != nil {
		t.Skip("requires an unwoven build")
	}
	if StartOwner(0, 1) || OwnerLive(0, 1) || EndOwner(0, 1) {
		t.Fatal("unwoven owner operation succeeded")
	}
}
