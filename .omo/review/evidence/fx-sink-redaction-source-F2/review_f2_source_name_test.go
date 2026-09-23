package testapp_test

// Reproducer for phase-2 finding sink-redaction-source-F2 (source name is
// serialized unchanged on a redacted source). Woven end-to-end: real
// net/http server, orchestrion-instrumented request sources and database/sql
// sink, and the serialized _dd.iast.json span tag, with the DEFAULT redaction
// patterns (copied verbatim from internal/config/config.go:38-39 because the
// harness init overrides them with never-match).

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
)

var (
	reviewDefaultName  = regexp.MustCompile(`(?i)(?:p(?:ass)?w(?:or)?d|pass(?:_?phrase)?|secret|(?:api_?|private_?|public_?|access_?|secret_?)key(?:_?id)?|token|consumer_?(?:id|key|secret)|sign(?:ed|ature)?|auth(?:entication|orization)?)`)
	reviewDefaultValue = regexp.MustCompile(`(?i)(?:bearer\s+[a-z0-9._-]+|token:[a-z0-9]{13}|glpat-[\w-]{20}|gh[opsu]_[0-9a-zA-Z]{36}|ey[I-L][\w=-]+\.ey[I-L][\w=-]+(?:\.[\w.+/=-]+)?|(?:-{5}BEGIN[a-z\s]+PRIVATE\sKEY-{5}[^-]+-{5}END[a-z\s]+PRIVATE\sKEY-{5}|ssh-rsa\s*[a-z0-9/.+]{100,}))`)
)

func withDefaultRedaction(t *testing.T) {
	t.Helper()
	oldName, oldValue, oldEnabled := config.RedactionNamePattern, config.RedactionValuePattern, config.RedactionEnabled
	config.RedactionNamePattern, config.RedactionValuePattern, config.RedactionEnabled = reviewDefaultName, reviewDefaultValue, true
	t.Cleanup(func() {
		config.RedactionNamePattern, config.RedactionValuePattern, config.RedactionEnabled = oldName, oldValue, oldEnabled
	})
}

// queryKeysToSQL is ordinary customer code: every query key reaches db.Exec.
func queryKeysToSQL(db *sql.DB) func(context.Context, *http.Request) {
	return func(ctx context.Context, r *http.Request) {
		for key := range r.URL.Query() {
			_, _ = db.ExecContext(ctx, key)
		}
	}
}

func reportLeak(t *testing.T, label, secret string, event any) {
	t.Helper()
	raw, _ := json.Marshal(event)
	t.Logf("%s event: %s", label, raw)
	if strings.Contains(string(raw), `"redacted":true`) && strings.Contains(string(raw), secret) {
		t.Errorf("LEAK[%s]: source redacted (redacted=true) but secret %q still serialized", label, secret)
	} else if strings.Contains(string(raw), secret) {
		t.Errorf("LEAK[%s]: secret %q serialized without redaction", label, secret)
	} else {
		t.Logf("NO-LEAK[%s]: %q absent from event", label, secret)
	}
}

// Finder's exact shape: key matches both the default name and value patterns.
func TestReviewF2QueryKeyNameAndValuePattern(t *testing.T) {
	requireWoven(t)
	withDefaultRedaction(t)
	const secret = "token:abcdefghijklm"
	event := requestEvent(t, queryKeysToSQL(openDB(t)), url.Values{secret: {"x"}})
	reportLeak(t, "query-key token:", secret, event)
}

// Classified sensitive ONLY by the value pattern (a GitHub PAT shape); the
// parameter-name origin sets Name == Value, so the redacted value leaks via Name.
func TestReviewF2QueryKeyValuePatternOnly(t *testing.T) {
	requireWoven(t)
	withDefaultRedaction(t)
	const secret = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
	if reviewDefaultName.MatchString(secret) || !reviewDefaultValue.MatchString(secret) {
		t.Fatal("precondition: must match value pattern only")
	}
	event := requestEvent(t, queryKeysToSQL(openDB(t)), url.Values{secret: {"x"}})
	reportLeak(t, "query-key ghp_", secret, event)
}

// Header-name origin (Name == Value) with a JWT-shaped header name.
func TestReviewF2HeaderNameValuePattern(t *testing.T) {
	requireWoven(t)
	withDefaultRedaction(t)
	const header = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"
	canonical := http.CanonicalHeaderKey(header)
	db := openDB(t)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://iast.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header[canonical] = []string{"v"}
	event := captureRequestEvent(t, func(ctx context.Context, r *http.Request) {
		for key := range r.Header {
			if strings.HasPrefix(strings.ToLower(key), "eyj") {
				_, _ = db.ExecContext(ctx, key)
			}
		}
	}, request)
	reportLeak(t, "header-name jwt", canonical, event)
}

// Control for the literal claim: a parameter classified by its NAME only.
// The name is a label ("password"); the secret is the value.
func TestReviewF2NameOnlyControl(t *testing.T) {
	requireWoven(t)
	withDefaultRedaction(t)
	const secret = "hunter2hunter2"
	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		_, _ = db.ExecContext(ctx, r.URL.Query().Get("password"))
	}, url.Values{"password": {secret}})
	reportLeak(t, "name-only password", secret, event)
	raw, _ := json.Marshal(event)
	if !strings.Contains(string(raw), `"name":"password"`) {
		t.Errorf("expected name label to be kept: %s", raw)
	}
}
