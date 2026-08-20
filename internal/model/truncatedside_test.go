// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model_test

import (
	"encoding/json"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTruncatedSideJSONRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		value  model.TruncatedSide
		wire   string
		isZero bool
	}{
		{name: "none", value: model.TruncatedSideNone, wire: "", isZero: true},
		{name: "right", value: model.TruncatedSideRight, wire: "right"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.wire, test.value.String())
			assert.Equal(t, test.isZero, test.value.IsZero())

			data, err := json.Marshal(test.value)
			require.NoError(t, err)
			assert.JSONEq(t, `"`+test.wire+`"`, string(data))

			var decoded model.TruncatedSide
			require.NoError(t, json.Unmarshal(data, &decoded))
			assert.Equal(t, test.value, decoded)
		})
	}
}

func TestTruncatedSideRejectsInvalidJSON(t *testing.T) {
	assert.Equal(t, "<invalid>", model.TruncatedSide(255).String())

	for _, data := range []string{`"left"`, `42`, `"unterminated`} {
		t.Run(data, func(t *testing.T) {
			value := model.TruncatedSideRight
			require.Error(t, json.Unmarshal([]byte(data), &value))
			assert.Equal(t, model.TruncatedSideRight, value)
		})
	}
}
