// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/config/loader"
)

func TestIndependent_WovenHTTPQueryNameLeaksThroughSQLSpan(t *testing.T) {
	requireWoven(t)
	const name = "token:abcdefghijklm"

	// The integration testapp overrides patterns in init. Restore the actual
	// environment-default pattern recorded before that test-only override.
	var defaultNamePattern *regexp.Regexp
	config.Observe(loader.Observer{RegisterDefault: func(key string, value any) {
		if key == config.EnvVarRedactionNamePattern {
			defaultNamePattern, _ = value.(*regexp.Regexp)
		}
	}})
	if defaultNamePattern == nil || !defaultNamePattern.MatchString(name) {
		t.Fatal("the default name-redaction pattern did not match the HTTP key")
	}
	previousPattern := config.RedactionNamePattern
	config.RedactionNamePattern = defaultNamePattern
	t.Cleanup(func() { config.RedactionNamePattern = previousPattern })
	t.Logf("woven: redaction=%t default_name_matches=%t", config.RedactionEnabled, defaultNamePattern.MatchString(name))

	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, request *http.Request) {
		query := request.URL.Query().Get(name)
		if _, err := db.ExecContext(ctx, query); err != nil {
			t.Errorf("database/sql ExecContext: %v", err)
		}
	}, url.Values{name: {"SELECT 1"}})
	wire, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range event.Sources {
		if source.Name == name && source.Redacted {
			t.Fatalf("LEAK: real HTTP-to-database/sql span serialized sensitive source name: %s", wire)
		}
	}
	t.Fatalf("HTTP-to-database/sql path did not produce expected source; event=%s", wire)
}
