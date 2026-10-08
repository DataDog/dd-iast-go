// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package urlbridge_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/urlbridge"
	"github.com/stretchr/testify/require"
)

func TestQueryCallback(t *testing.T) {
	called := false
	urlbridge.Register(func(object any, values map[string][]string) map[string][]string {
		called = object != nil
		values["managed"] = []string{"value"}
		return values
	})
	values := urlbridge.Query(new(int), map[string][]string{})
	require.True(t, called)
	require.Equal(t, []string{"value"}, values["managed"])
}
