// Independent phase-3 verification for sink-redaction-source-F1 through the
// realistic surface: a woven (orchestrion) HTTP server source flowing into a
// database/sql sink, with the built-in default redaction configuration.
package testapp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/taint"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
)

// TestFXPasswordPatternLeakE2E sends password=abc as an HTTP query parameter,
// concatenates it into a SQL statement executed through database/sql, and
// checks that the raw secret never appears in the serialized vulnerability
// event even though the source is reported as redacted.
func TestFXPasswordPatternLeakE2E(t *testing.T) {
	requireWoven(t)
	const secret = "abc"

	// The package init() disables name-based redaction for its own tests;
	// restore a realistic built-in-equivalent name policy for this request.
	previousName := config.RedactionNamePattern
	config.RedactionNamePattern = regexp.MustCompile(`(?i)(?:p(?:ass)?w(?:or)?d|pass(?:_?phrase)?|secret|token)`)
	t.Cleanup(func() { config.RedactionNamePattern = previousName })

	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		password := r.URL.Query().Get("password")
		t.Logf("password tainted: %v", taint.IsTaintedString(password))
		query := testapp.FXBuildPasswordQuery(password)
		t.Logf("query tainted: %v", taint.IsTaintedString(query))
		stmt, err := db.PrepareContext(ctx, query)
		if err != nil {
			t.Error(err)
			return
		}
		defer stmt.Close()
		if _, err := stmt.ExecContext(ctx); err != nil {
			t.Error(err)
		}
	}, url.Values{"password": {secret}})

	if len(event.Vulnerabilities) == 0 {
		t.Fatal("no vulnerability reported; e2e harness did not exercise the sink")
	}
	for _, source := range event.Sources {
		if source.Name == "password" {
			if !source.Redacted {
				t.Errorf("password source not marked redacted: %#v", source)
			}
			if source.Pattern == secret {
				t.Errorf("LEAK redacted model.Source.Pattern equals the secret: %#v", source)
			}
		}
	}
	for _, vulnerability := range event.Vulnerabilities {
		if vulnerability.Evidence == nil {
			continue
		}
		for _, part := range vulnerability.Evidence.ValueParts {
			if part.Redacted && part.Pattern == secret {
				t.Errorf("LEAK redacted evidence ValuePart.Pattern equals the secret: %#v", part)
			}
		}
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), `"`+secret+`"`) {
		t.Fatalf("LEAK serialized event contains the raw password: %s", payload)
	}
	t.Logf("serialized event: %s", payload)
}
