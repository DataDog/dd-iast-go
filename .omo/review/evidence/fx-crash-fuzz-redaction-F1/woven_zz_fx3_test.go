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
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
)

// Copied verbatim from internal/config/config.go:38-39 (defaults).
const (
	fx3DefaultName  = `(?i)(?:p(?:ass)?w(?:or)?d|pass(?:_?phrase)?|secret|(?:api_?|private_?|public_?|access_?|secret_?)key(?:_?id)?|token|consumer_?(?:id|key|secret)|sign(?:ed|ature)?|auth(?:entication|orization)?)`
	fx3DefaultValue = `(?i)(?:bearer\s+[a-z0-9._-]+|token:[a-z0-9]{13}|glpat-[\w-]{20}|gh[opsu]_[0-9a-zA-Z]{36}|ey[I-L][\w=-]+\.ey[I-L][\w=-]+(?:\.[\w.+/=-]+)?|(?:-{5}BEGIN[a-z\s]+PRIVATE\sKEY-{5}[^-]+-{5}END[a-z\s]+PRIVATE\sKEY-{5}|ssh-rsa\s*[a-z0-9/.+]{100,}))`
)

func TestFx3WovenOracleQuoteDesync(t *testing.T) {
	requireWoven(t)
	oldName, oldValue := config.RedactionNamePattern, config.RedactionValuePattern
	config.RedactionNamePattern = regexp.MustCompile(fx3DefaultName)
	config.RedactionValuePattern = regexp.MustCompile(fx3DefaultValue)
	t.Cleanup(func() { config.RedactionNamePattern, config.RedactionValuePattern = oldName, oldValue })
	db := openDB(t)
	leaks := 0
	for _, note := range []string{"(urgent) call me back", "urgent call me back"} {
		const email = "jane.doe@example.com"
		var query string
		event := requestEvent(t, func(ctx context.Context, r *http.Request) {
			v := r.URL.Query()
			query = testapp.BuildTicketQuery(v.Get("note"), v.Get("email"))
			if _, err := db.ExecContext(ctx, query); err != nil {
				t.Error(err)
			}
		}, url.Values{"note": {note}, "email": {email}})
		if countType(event, constants.VulnerabilityTypeSqlInjection) == 0 {
			t.Fatalf("no SQLi reported for note=%q", note)
		}
		raw, _ := json.Marshal(event.Sources)
		t.Logf("note=%q query=%q", note, query)
		t.Logf("  sources=%s", raw)
		for _, v := range event.Vulnerabilities {
			ev, _ := json.Marshal(v.Evidence)
			t.Logf("  evidence=%s", ev)
			if strings.Contains(string(ev), "jane") || strings.Contains(string(ev), "call me") {
				leaks++
				t.Logf("  LEAK: raw user value in evidence")
			}
		}
		if strings.Contains(string(raw), "jane.doe") || strings.Contains(string(raw), "call me") {
			leaks++
			t.Logf("  LEAK: raw user value in sources")
		}
	}
	if leaks > 0 {
		t.Errorf("%d leaks of SQL-literal user values with default redaction config", leaks)
	}
}
