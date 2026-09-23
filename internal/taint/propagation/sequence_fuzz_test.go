// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import "testing"

func FuzzEngineSequence(f *testing.F) {
	f.Add([]byte("ascii-repeated-values"))
	f.Add([]byte("unicode-\u00e9-\u03bb-\u4e16\u754c"))
	f.Add([]byte{0xff, 0xfe, 'a', 0x80, 'a', 0xc3, 0xa9})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > sequenceMaxInput {
			encoded = encoded[:sequenceMaxInput]
		}
		taintStore, _ := beginScope(t)
		runEngineSequence(t, taintStore, encoded)
	})
}
