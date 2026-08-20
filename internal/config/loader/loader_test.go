// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package loader_test

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config/loader"
	"github.com/DataDog/dd-iast-go/internal/config/parser"
)

type registration struct {
	name   string
	value  any
	origin parser.Origin
}

type recorder struct {
	warnings      []string
	registrations []registration
}

func (r *recorder) observer() loader.Observer {
	return loader.Observer{
		Warn: func(format string, args ...any) {
			r.warnings = append(r.warnings, fmt.Sprintf(format, args...))
		},
		RegisterDefault: func(name string, value any) {
			r.registrations = append(r.registrations, registration{name: name, value: value, origin: parser.OriginDefault})
		},
		RegisterEnvironment: func(name string, value any) {
			r.registrations = append(r.registrations, registration{name: name, value: value, origin: parser.OriginEnvVar})
		},
	}
}

func unsetEnv(t *testing.T, name string) {
	t.Helper()
	previous, wasSet := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatalf("Unsetenv(%q): %v", name, err)
	}
	t.Cleanup(func() {
		var err error
		if wasSet {
			err = os.Setenv(name, previous)
		} else {
			err = os.Unsetenv(name)
		}
		if err != nil {
			t.Errorf("restore environment variable %q: %v", name, err)
		}
	})
}

func assertObservation(t *testing.T, got *recorder, wantWarnings []string, wantRegistration registration) {
	t.Helper()
	if !reflect.DeepEqual(got.warnings, wantWarnings) {
		t.Errorf("warnings = %#v, want %#v", got.warnings, wantWarnings)
	}
	if len(got.registrations) != 1 {
		t.Fatalf("registration count = %d, want 1", len(got.registrations))
	}
	if !reflect.DeepEqual(got.registrations[0], wantRegistration) {
		t.Errorf("registration = %#v, want %#v", got.registrations[0], wantRegistration)
	}
}

func TestBoolFromEnv(t *testing.T) {
	const envVar = "DD_IAST_GO_TEST_LOADER_BOOL"

	t.Run("default", func(t *testing.T) {
		unsetEnv(t, envVar)
		var observed recorder
		if got := loader.BoolFromEnv(observed.observer(), envVar, true); !got {
			t.Error("BoolFromEnv() = false, want true")
		}
		assertObservation(t, &observed, nil, registration{envVar, true, parser.OriginDefault})
	})

	t.Run("environment", func(t *testing.T) {
		t.Setenv(envVar, "false")
		var observed recorder
		if got := loader.BoolFromEnv(observed.observer(), envVar, true); got {
			t.Error("BoolFromEnv() = true, want false")
		}
		assertObservation(t, &observed, nil, registration{envVar, false, parser.OriginEnvVar})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Setenv(envVar, "invalid")
		var observed recorder
		if got := loader.BoolFromEnv(observed.observer(), envVar, true); !got {
			t.Error("BoolFromEnv() = false, want default true")
		}
		assertObservation(t, &observed,
			[]string{"invalid value for DD_IAST_GO_TEST_LOADER_BOOL (expected boolean): invalid"},
			registration{envVar, true, parser.OriginDefault},
		)
	})
}

func TestUintFromEnv(t *testing.T) {
	const envVar = "DD_IAST_GO_TEST_LOADER_UINT"

	t.Run("environment", func(t *testing.T) {
		t.Setenv(envVar, "42")
		var observed recorder
		if got := loader.UintFromEnv(observed.observer(), envVar, 7); got != 42 {
			t.Errorf("UintFromEnv() = %d, want 42", got)
		}
		assertObservation(t, &observed, nil, registration{envVar, uint64(42), parser.OriginEnvVar})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Setenv(envVar, "invalid")
		var observed recorder
		if got := loader.UintFromEnv(observed.observer(), envVar, 7); got != 7 {
			t.Errorf("UintFromEnv() = %d, want default 7", got)
		}
		assertObservation(t, &observed,
			[]string{"invalid value for DD_IAST_GO_TEST_LOADER_UINT (expected integer): invalid"},
			registration{envVar, uint64(7), parser.OriginDefault},
		)
	})
}

func TestUintFromEnvBounded(t *testing.T) {
	const envVar = "DD_IAST_GO_TEST_LOADER_BOUNDED"
	tests := []struct {
		name         string
		value        string
		want         uint8
		wantOrigin   parser.Origin
		wantWarnings []string
	}{
		{name: "within bounds", value: "42", want: 42, wantOrigin: parser.OriginEnvVar},
		{
			name:       "below minimum",
			value:      "2",
			want:       10,
			wantOrigin: parser.OriginEnvVar,
			wantWarnings: []string{
				"invalid value for DD_IAST_GO_TEST_LOADER_BOUNDED (expected integer between 10 and 100): 2",
			},
		},
		{
			name:       "above maximum",
			value:      "500",
			want:       100,
			wantOrigin: parser.OriginEnvVar,
			wantWarnings: []string{
				"invalid value for DD_IAST_GO_TEST_LOADER_BOUNDED (expected integer between 10 and 100): 500",
			},
		},
		{
			name:       "invalid uses default",
			value:      "invalid",
			want:       10,
			wantOrigin: parser.OriginDefault,
			wantWarnings: []string{
				"invalid value for DD_IAST_GO_TEST_LOADER_BOUNDED (expected integer): invalid",
				"invalid value for DD_IAST_GO_TEST_LOADER_BOUNDED (expected integer between 10 and 100): 5",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(envVar, test.value)
			var observed recorder
			got := loader.UintFromEnvBounded(observed.observer(), envVar, 5, uint8(10), uint8(100))
			if got != test.want {
				t.Errorf("UintFromEnvBounded() = %d, want %d", got, test.want)
			}
			assertObservation(t, &observed, test.wantWarnings, registration{envVar, test.want, test.wantOrigin})
		})
	}
}

func TestFromEnv(t *testing.T) {
	const envVar = "DD_IAST_GO_TEST_LOADER_PARSE"

	t.Run("environment", func(t *testing.T) {
		t.Setenv(envVar, "42")
		var observed recorder
		if got := loader.FromEnv(observed.observer(), envVar, 7, strconv.Atoi); got != 42 {
			t.Errorf("FromEnv() = %d, want 42", got)
		}
		assertObservation(t, &observed, nil, registration{envVar, 42, parser.OriginEnvVar})
	})

	t.Run("invalid", func(t *testing.T) {
		t.Setenv(envVar, "invalid")
		var observed recorder
		if got := loader.FromEnv(observed.observer(), envVar, 7, strconv.Atoi); got != 7 {
			t.Errorf("FromEnv() = %d, want default 7", got)
		}
		assertObservation(t, &observed,
			[]string{"invalid value for DD_IAST_GO_TEST_LOADER_PARSE: invalid"},
			registration{envVar, 7, parser.OriginDefault},
		)
	})
}
