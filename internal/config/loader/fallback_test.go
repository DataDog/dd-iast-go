// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package loader_test

import (
	"strconv"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config/loader"
	"github.com/DataDog/dd-iast-go/internal/config/parser"
)

func TestFromEnvWithFallback(t *testing.T) {
	const canonical = "DD_IAST_GO_TEST_CANONICAL"
	const fallback = "DD_IAST_GO_TEST_FALLBACK"
	tests := []struct {
		name      string
		canonical *string
		fallback  *string
		want      int
		origin    parser.Origin
		warnings  []string
	}{
		{name: "default", want: 7, origin: parser.OriginDefault},
		{name: "fallback", fallback: stringPointer("8"), want: 8, origin: parser.OriginEnvVar},
		{name: "canonical", canonical: stringPointer("9"), fallback: stringPointer("8"), want: 9, origin: parser.OriginEnvVar},
		{name: "invalid canonical wins", canonical: stringPointer("bad"), fallback: stringPointer("8"), want: 7, origin: parser.OriginDefault,
			warnings: []string{"invalid value for " + canonical + ": bad"}},
		{name: "invalid fallback", fallback: stringPointer("bad"), want: 7, origin: parser.OriginDefault,
			warnings: []string{"invalid value for " + fallback + ": bad"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			unsetEnv(t, canonical)
			unsetEnv(t, fallback)
			if test.canonical != nil {
				t.Setenv(canonical, *test.canonical)
			}
			if test.fallback != nil {
				t.Setenv(fallback, *test.fallback)
			}
			var observed recorder
			got := loader.FromEnvWithFallback(observed.observer(), canonical, fallback, 7, strconv.Atoi)
			if got != test.want {
				t.Fatalf("value = %d, want %d", got, test.want)
			}
			assertObservation(t, &observed, test.warnings, registration{canonical, test.want, test.origin})
		})
	}
}

func stringPointer(value string) *string { return &value }
