// Independent phase-3 verification reproducer for phase-2 finding sink-evidence-F1.
//
// Claim under test: CollectJoinedStrings can collect unsafe ranges from more
// than four distinct active request owners, but Snapshot.addOwner silently
// keeps only four owner identities. When the only bound request span belongs
// to a fifth contributing owner and the sink context carries no span, span
// selection cannot find that owner and the report is attached to an orphan
// span instead of the contributing request's trace.
package vulnerability_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/iast/os/exec"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

// fxConfigure mirrors a supported customer configuration
// DD_IAST_MAX_CONCURRENT_REQUESTS>=5 (default 2 cannot host five concurrent
// owners). Deduplication is disabled so several subtests can share a process.
func fxConfigure(t *testing.T) {
	t.Helper()
	oldEnabled, oldSampling, oldConcurrent := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	oldDedup, oldStack, oldVulns := config.DeduplicationEnabled, config.StackTraceEnabled, config.VulnerabilitiesPerRequest
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 8
	config.DeduplicationEnabled = false
	config.StackTraceEnabled = false
	config.VulnerabilitiesPerRequest = 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = oldEnabled, oldSampling, oldConcurrent
		config.DeduplicationEnabled, config.StackTraceEnabled, config.VulnerabilitiesPerRequest = oldDedup, oldStack, oldVulns
	})
}

func fxBeginOwners(t *testing.T, n int) (argv []string, scopes []*request.Scope) {
	t.Helper()
	argv = []string{"echo"}
	for index := 0; index < n; index++ {
		ctx, scope, created := request.Begin(context.Background())
		if !created || !scope.Active() {
			t.Fatalf("owner %d was not admitted as an active analysis", index)
		}
		scopes = append(scopes, scope)
		t.Cleanup(scope.Finish)
		argument := taint.TaintString(ctx, taint.Source{
			Origin: constants.OriginHttpRequestParameter,
			Name:   fmt.Sprintf("fx-argument-%d", index),
		}, fmt.Sprintf("fx-value-%d", index))
		argv = append(argv, argument)
	}
	return argv, scopes
}

func fxAnnotationVulnCount(annotation *spans.Annotation) int {
	annotation.RLock()
	defer annotation.RUnlock()
	return len(annotation.Vulnerabilities)
}

func fxOwnerIdentity(t *testing.T, scope *request.Scope) (index uint8, id, generation uint64) {
	t.Helper()
	analysis, ok := scope.Analysis()
	if !ok {
		t.Fatal("scope has no analysis")
	}
	index, id, generation, ok = analysis.Identity()
	if !ok {
		t.Fatal("analysis identity unavailable")
	}
	return index, id, generation
}

func fxSnapshotHasOwner(t *testing.T, snapshot *evidence.Snapshot, index uint8, id, generation uint64) bool {
	t.Helper()
	for i := 0; i < snapshot.OwnerCount(); i++ {
		if owner, ok := snapshot.OwnerAt(i); ok && owner.Index == index && owner.ID == id && owner.Generation == generation {
			return true
		}
	}
	return false
}

// TestFxDirectCollectionDropsFifthOwnerIdentity: five distinct owners
// contribute unsafe ranges, but only four owner identities survive.
func TestFxDirectCollectionDropsFifthOwnerIdentity(t *testing.T) {
	fxConfigure(t)
	argv, scopes := fxBeginOwners(t, 5)
	query := strings.Join(argv, " ")

	snapshot, status := evidence.CollectJoinedStrings(argv, " ", query, constants.VulnerabilityTypeCommandInjection)
	if status != evidence.StatusCollected {
		t.Fatalf("collection status = %v, want StatusCollected", status)
	}
	if got := snapshot.OwnerCount(); got != 4 {
		t.Fatalf("snapshot owner identities = %d, want 4 (fifth contributing owner silently dropped)", got)
	}
	index, id, generation := fxOwnerIdentity(t, scopes[4])
	if fxSnapshotHasOwner(t, snapshot, index, id, generation) {
		t.Fatal("fifth contributing owner identity survived; expected addOwner to drop it")
	}
}

// TestFxJoinedReportOrphansFifthBoundOwner: with no span in the sink context
// and the fifth (truncated) contributing owner the only one with a bound
// span, the report lands on an orphan span, not on the bound request span.
func TestFxJoinedReportOrphansFifthBoundOwner(t *testing.T) {
	fxConfigure(t)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	argv, scopes := fxBeginOwners(t, 5)
	span := tracer.StartSpan("fx-fifth-owner")
	annotation := spans.BindScope(span, scopes[4])
	if annotation == nil {
		t.Fatal("fifth owner span did not bind")
	}
	t.Cleanup(func() {
		spans.Finished(span)
		span.Finish()
	})

	exec.Report(context.Background(), argv)

	if got := fxAnnotationVulnCount(annotation); got != 0 {
		t.Fatalf("fifth bound owner reports = %d, want 0 (its identity was truncated from the snapshot)", got)
	}
	if got := len(mock.FinishedSpans()); got != 1 {
		t.Fatalf("finished spans = %d, want 1 orphan span carrying the report", got)
	}
}

// TestFxControlFourthBoundOwnerFound: the identical flow with a bound owner
// inside the four-identity cap reports on that owner's span, isolating the
// defect to the fifth-owner truncation.
func TestFxControlFourthBoundOwnerFound(t *testing.T) {
	fxConfigure(t)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	argv, scopes := fxBeginOwners(t, 4)
	span := tracer.StartSpan("fx-fourth-owner")
	annotation := spans.BindScope(span, scopes[3])
	if annotation == nil {
		t.Fatal("fourth owner span did not bind")
	}
	t.Cleanup(func() {
		spans.Finished(span)
		span.Finish()
	})

	exec.Report(context.Background(), argv)

	if got := fxAnnotationVulnCount(annotation); got != 1 {
		t.Fatalf("fourth bound owner reports = %d, want 1", got)
	}
	if got := len(mock.FinishedSpans()); got != 0 {
		t.Fatalf("finished orphan spans = %d, want 0", got)
	}
}
