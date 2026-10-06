// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build goexperiment.jsonv2

package stream_test

import "testing"

// With GOEXPERIMENT=jsonv2 (the default from Go 1.27), encoding/json uses the
// v2 implementation: the hooks of the v1 files do not apply (plan section 6.1
// rule 6, as PR #39 variant_v2_test.go).
func TestJSONVariantV2(t *testing.T) {
	t.Skip("encoding/json v2 (GOEXPERIMENT=jsonv2): the encoding/json hooks apply only to v1")
}
