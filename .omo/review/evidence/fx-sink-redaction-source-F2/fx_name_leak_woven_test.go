// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product contains software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

// Independent phase-3 verification of sink-redaction-source-F2 on the full
// woven surface: real HTTP request -> lazy query-parameter source -> database/sql
// prepare+exec sinks -> event captured from the finished span. The package
// init in e2e_test.go overrides the built-in redaction patterns with
// `never-match`, so this test restores the documented defaults from
// internal/config/config.go verbatim before running.

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

const fxDefaultNamePattern = `(?i)(?:p(?:ass)?w(?:or)?d|pass(?:_?phrase)?|secret|(?:api_?|private_?|public_?|access_?|secret_?)key(?:_?id)?|token|consumer_?(?:id|key|secret)|sign(?:ed|ature)?|auth(?:entication|orization)?)`
const fxDefaultValuePattern = `(?i)(?:bearer\s+[a-z0-9._-]+|token:[a-z0-9]{13}|glpat-[\w-]{20}|gh[opsu]_[0-9a-zA-Z]{36}|ey[I-L][\w=-]+\.ey[I-L][\w=-]+(?:\.[\w.+/=-]+)?|(?:-{5}BEGIN[a-z\s]+PRIVATE\sKEY-{5}[^-]+-{5}END[a-z\s]+PRIVATE\sKEY-{5}|ssh-rsa\s*[a-z0-9/.+]{100,}))`

func TestFxSensitiveSourceNameLeavesProcessUnredacted(t *testing.T) {
	requireWoven(t)
	config.RedactionEnabled = true
	config.RedactionNamePattern = regexp.MustCompile(fxDefaultNamePattern)
	config.RedactionValuePattern = regexp.MustCompile(fxDefaultValuePattern)
	t.Cleanup(func() {
		config.RedactionNamePattern = regexp.MustCompile(`never-match`)
		config.RedactionValuePattern = regexp.MustCompile(`never-match`)
	})
	db := openDB(t)
	const credentialShapedName = "token:abcdefghijklm"
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		query := r.URL.Query().Get(credentialShapedName)
		stmt, err := db.PrepareContext(ctx, query)
		if err != nil {
			t.Error(err)
			return
		}
		defer stmt.Close()
		if _, err = stmt.ExecContext(ctx); err != nil {
			t.Error(err)
		}
	}, url.Values{credentialShapedName: {"SELECT 1"}})
	if countType(event, constants.VulnerabilityTypeSqlInjection) == 0 {
		t.Fatalf("no SQL finding was reported; event sources=%d vulnerabilities=%d", len(event.Sources), len(event.Vulnerabilities))
	}
	for _, source := range event.Sources {
		if source.Origin == constants.OriginHttpRequestParameter && source.Name == credentialShapedName {
			t.Fatalf("LEAK: credential-shaped source name left the process unredacted: %+v", source)
		}
	}
}
