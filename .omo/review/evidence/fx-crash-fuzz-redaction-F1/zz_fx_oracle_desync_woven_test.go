package testapp_test

import (
	"bytes"
	"context"
	stdsql "database/sql"
	"encoding/json"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/orchestrion/runtime/built"
)

// fx-crash-fuzz-redaction-F1: woven end-to-end. Customer code concatenates a
// tainted request parameter into a query with plain '+', after an ordinary
// literal 'Q'. The encoded span event must not contain the raw value.
func TestFXOracleQuoteDesyncWoven(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled")
	}
	for _, state := range []string{"Q", "P"} {
		t.Run(state, func(t *testing.T) {
			mock := mocktracer.Start()
			defer mock.Stop()
			ctx, scope, created := request.Begin(context.Background())
			if !created {
				t.Fatal("no scope")
			}
			span, spanCtx := tracer.StartSpanFromContext(ctx, "request")
			annotation := spans.BindScope(span, scope)
			email := taint.TaintString(spanCtx, taint.Source{Origin: constants.OriginHttpRequestParameter, Name: "email"}, "alice.fx@example.com")
			parts := []string{"INSERT INTO contacts (kind, tag, phone, email) VALUES ('" + state + "','a','+33612','", email, "')"}
			query := parts[0] + parts[1] + parts[2]
			query = propagation.JoinString(parts, "", query)
			db, err := stdsql.Open(testDriverName, "")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.ExecContext(spanCtx, query); err != nil {
				t.Fatal(err)
			}
			annotation.RLock()
			n := len(annotation.Vulnerabilities)
			data, _ := json.Marshal(&annotation.Event)
			msg, _ := annotation.Event.MarshalMsg(nil)
			annotation.RUnlock()
			spans.Finished(span)
			scope.Finish()
			span.Finish()
			leak := bytes.Contains(data, []byte("alice.fx")) || bytes.Contains(msg, []byte("alice.fx"))
			t.Logf("state=%s vulnerabilities=%d leak=%t event=%s", state, n, leak, data)
			if n != 1 {
				t.Fatalf("expected 1 SQLi finding, got %d", n)
			}
			if leak {
				t.Errorf("LEAK: raw tainted value in span event payload (state=%s)", state)
			}
		})
	}
}
