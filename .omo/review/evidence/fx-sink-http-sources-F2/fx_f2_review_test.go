package http_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

type fxQueryObservation struct {
	Mode             string `json:"mode"`
	Sort             string `json:"sort"`
	SortOrigin       string `json:"sort_origin"`
	SortRanges       int    `json:"sort_ranges"`
	StatementTainted bool   `json:"statement_tainted"`
	FormValue        string `json:"form_value"`
	FormValueOrigin  string `json:"form_value_origin"`
	FormValueRanges  int    `json:"form_value_ranges"`
}

func fxOrigin(value string) (string, int) {
	var origin string
	n := 0
	taint.VisitString(value, func(r taint.Range) bool {
		origin = r.Source.Origin.String()
		n++
		return true
	})
	return origin, n
}

// fxDefaultingEndpoint is an ordinary server handler that normalizes the
// request query in place (a common "apply defaults" middleware pattern) and
// then reads it back to build a SQL statement.
func fxDefaultingEndpoint(w http.ResponseWriter, req *http.Request) {
	mode := req.URL.Query().Get("mode")
	switch mode {
	case "literal":
		// Replace the query with a trusted literal.
		req.URL.RawQuery = "sort=created_at"
	case "default":
		// Keep the request's parameters but add a trusted default.
		q := req.URL.Query()
		if q.Get("sort") == "" {
			q.Set("sort", "created_at")
		}
		req.URL.RawQuery = q.Encode()
	}
	sort := req.URL.Query().Get("sort")
	statement := "SELECT * FROM items ORDER BY " + sort
	formValue := req.FormValue("sort")
	got := fxQueryObservation{Mode: mode, Sort: sort, StatementTainted: taint.IsTaintedString(statement), FormValue: formValue}
	got.SortOrigin, got.SortRanges = fxOrigin(sort)
	got.FormValueOrigin, got.FormValueRanges = fxOrigin(formValue)
	_ = json.NewEncoder(w).Encode(got)
}

func TestFxF2_ReplacedQueryAttribution(t *testing.T) {
	testConfig(t, 100, 1)
	mockTracer := mocktracer.Start()
	defer mockTracer.Stop()
	server := httptest.NewServer(http.HandlerFunc(fxDefaultingEndpoint))
	defer server.Close()

	for _, path := range []string{
		"/items?mode=literal&sort=attacker_col",
		"/items?mode=default",
		"/items?mode=default&sort=attacker_col",
	} {
		response, err := server.Client().Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		var got fxQueryObservation
		if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		t.Logf("%s => sort=%q origin=%q ranges=%d statement_tainted=%t | FormValue=%q origin=%q ranges=%d",
			path, got.Sort, got.SortOrigin, got.SortRanges, got.StatementTainted,
			got.FormValue, got.FormValueOrigin, got.FormValueRanges)
		if got.Sort == "created_at" && got.SortRanges > 0 {
			t.Errorf("FALSE PROVENANCE: application literal %q attributed to %q via URL.Query", got.Sort, got.SortOrigin)
		}
		if got.FormValue == "created_at" && got.FormValueRanges > 0 {
			t.Errorf("FALSE PROVENANCE: application literal %q attributed to %q via FormValue", got.FormValue, got.FormValueOrigin)
		}
		if built.WithOrchestrion && got.Sort == "attacker_col" && got.SortRanges == 0 {
			t.Errorf("control: attacker value lost taint")
		}
	}
}
