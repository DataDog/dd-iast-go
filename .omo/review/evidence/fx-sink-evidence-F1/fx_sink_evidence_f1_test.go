package vulnerability_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
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

func TestFXSinkEvidenceFifthOwnerOmission(t *testing.T) {
	configureTaintedReportTest(t)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)

	config.MaxConcurrentRequests = 2
	defaultScopes := make([]*request.Scope, 0, 3)
	defaultAdmitted := 0
	for index := range 3 {
		_, scope, created := request.Begin(context.Background())
		if !created {
			t.Fatalf("default-cap scope %d was not created", index)
		}
		defaultScopes = append(defaultScopes, scope)
		if scope.Active() {
			defaultAdmitted++
		} else if scope.Decision() != request.DecisionCapacityDropped {
			t.Fatalf("default-cap scope %d decision = %v", index, scope.Decision())
		}
	}
	for _, scope := range defaultScopes {
		scope.Finish()
	}
	if defaultAdmitted != 2 {
		t.Fatalf("default cap admitted %d scopes, want 2", defaultAdmitted)
	}

	config.MaxConcurrentRequests = 5
	arguments := []string{"echo"}
	scopes := make([]*request.Scope, 0, 5)
	for index := range 5 {
		ctx, scope, created := request.Begin(context.Background())
		if !created || !scope.Active() {
			t.Fatalf("configured-cap request %d was not admitted", index)
		}
		scopes = append(scopes, scope)
		t.Cleanup(scope.Finish)
		argument := taint.TaintString(ctx, taint.Source{
			Origin: constants.OriginHttpRequestParameter,
			Name:   fmt.Sprintf("argument-%d", index),
		}, fmt.Sprintf("value-%d", index))
		arguments = append(arguments, argument)
	}

	query := strings.Join(arguments, " ")
	snapshot, status := evidence.CollectJoinedStrings(arguments, " ", query, constants.VulnerabilityTypeCommandInjection)
	if status != evidence.StatusCollected || snapshot.SourceCount() != 5 || snapshot.OwnerCount() != 4 {
		t.Fatalf("collection status=%v sources=%d owners=%d; want collected, 5 sources, 4 owners", status, snapshot.SourceCount(), snapshot.OwnerCount())
	}
	fifthAnalysis, active := scopes[4].Analysis()
	fifthIndex, fifthID, fifthGeneration, identified := fifthAnalysis.Identity()
	if !active || !identified {
		t.Fatal("fifth contributing owner is not live")
	}
	fifthRetained := false
	for index := 0; index < snapshot.OwnerCount(); index++ {
		owner, ok := snapshot.OwnerAt(index)
		if ok && owner.Index == fifthIndex && owner.ID == fifthID && owner.Generation == fifthGeneration {
			fifthRetained = true
		}
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
	reportCommitted := vulnerability.ReportTainted(
		context.Background(),
		constants.VulnerabilityTypeCommandInjection,
		snapshot,
		redaction.AnalyzeCommand(arguments),
		2,
		sqlSkipPolicy(),
	)
	annotation.RLock()
	fifthReports := len(annotation.Vulnerabilities)
	annotation.RUnlock()
	orphanSpans := len(mock.FinishedSpans())

	t.Logf("default_max_concurrent=2 admitted=%d third=capacity_dropped; configured_max_concurrent=5 admitted=5; sources=%d snapshot_owners=%d fifth_owner_retained=%t report_committed=%t fifth_owner_vulnerabilities=%d orphan_spans=%d",
		defaultAdmitted, snapshot.SourceCount(), snapshot.OwnerCount(), fifthRetained, reportCommitted, fifthReports, orphanSpans)
	if fifthRetained || !reportCommitted || fifthReports != 0 || orphanSpans != 1 {
		t.Fatalf("unexpected owner-fanout result: fifth_retained=%t committed=%t fifth_reports=%d orphans=%d", fifthRetained, reportCommitted, fifthReports, orphanSpans)
	}
}
