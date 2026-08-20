// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model_test

import (
	"encoding/json"
	"reflect"
	"testing"
)

func assertJSONEqual(t *testing.T, want, got string) {
	t.Helper()
	var wantValue, gotValue any
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Fatalf("decode expected JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(got), &gotValue); err != nil {
		t.Fatalf("decode actual JSON: %v", err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Errorf("JSON value = %s, want %s", got, want)
	}
}

func mustJSONMarshal(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(): %v", err)
	}
	return data
}
