package vulnerability_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/redaction"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func TestJoinedEvidenceFindsFifthBoundOwner(t *testing.T) {
	// Given five independently tainted command arguments, only the fifth
	// request owner has a root span.
	configureTaintedReportTest(t)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	arguments := []string{"echo"}
	scopes := make([]*request.Scope, 0, 5)
	for index := range 5 {
		ctx, scope, created := request.Begin(context.Background())
		if !created || !scope.Active() {
			t.Fatalf("request %d was not admitted", index)
		}
		scopes = append(scopes, scope)
		t.Cleanup(scope.Finish)
		argument := taint.TaintString(ctx, taint.Source{
			Origin: constants.OriginHttpRequestParameter,
			Name:   fmt.Sprintf("argument-%d", index),
		}, fmt.Sprintf("value-%d", index))
		arguments = append(arguments, argument)
	}
	span := tracer.StartSpan("fifth-owner")
	t.Cleanup(func() {
		spans.Finished(span)
		span.Finish()
	})
	annotation := spans.BindScope(span, scopes[4])
	if annotation == nil {
		t.Fatal("fifth owner did not bind to its span")
	}
	query := strings.Join(arguments, " ")

	// When the command sink reports without an explicit span context.
	snapshot, status := evidence.CollectJoinedStrings(arguments, " ", query, constants.VulnerabilityTypeCommandInjection)
	if status != evidence.StatusCollected {
		t.Fatalf("collection status = %v", status)
	}
	if !vulnerability.ReportTainted(context.Background(), constants.VulnerabilityTypeCommandInjection, snapshot, redaction.AnalyzeCommand(arguments), 2, sqlSkipPolicy()) {
		t.Fatal("command report was dropped")
	}

	// Then the report belongs to the only bound contributing request owner.
	annotation.RLock()
	count := len(annotation.Vulnerabilities)
	annotation.RUnlock()
	if count != 1 {
		t.Fatalf("fifth owner reports = %d, snapshot owners = %d, orphan spans = %d; want 1 report on fifth owner", count, snapshot.OwnerCount(), len(mock.FinishedSpans()))
	}
}
