// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package constants_test

import (
	"testing"

	"github.com/tinylib/msgp/msgp"
)

// encodeMsgpString encodes s as a MessagePack string, for use in negative
// test cases that need syntactically valid-but-semantically-invalid payloads.
func encodeMsgpString(s string) []byte {
	return msgp.AppendString(nil, s)
}

func assertNotPanics(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Errorf("%s panicked: %v", name, recovered)
		}
	}()
	f()
}
