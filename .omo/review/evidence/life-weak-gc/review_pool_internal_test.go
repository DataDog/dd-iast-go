// Review reproducer for node life-weak-gc. Not for commit.

package spans

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

// F4: with dd-trace-go's span pool (DD_TRACER_EXPERIMENTAL_SPAN_POOL_ENABLED /
// tracer.WithSpanPool), a *tracer.Span is recycled for a new trace. weak.Make
// of the recycled object equals the old key and Value() is non-nil, so a store
// entry created after the old root finished is inherited by the new root.
func TestReviewSpanPoolRecycledRootInheritsStaleAnnotation(t *testing.T) {
	for _, variant := range []string{"sampled-bleed", "negative-starve"} {
		t.Run(variant, func(t *testing.T) {
			runPoolVariant(t, variant)
		})
	}
}

func runPoolVariant(t *testing.T, variant string) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	defer agent.Close()
	t.Setenv("DD_INSTRUMENTATION_TELEMETRY_ENABLED", "false")
	t.Setenv("DD_REMOTE_CONFIGURATION_ENABLED", "false")
	t.Setenv("DD_TRACE_STARTUP_LOGS", "false")
	prevProcs := runtime.GOMAXPROCS(1) // one P: sync.Pool private slot is shared by worker and test goroutine
	defer runtime.GOMAXPROCS(prevProcs)
	enabled, rate, capacity := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	defer func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = enabled, rate, capacity
	}()
	store.Clear()
	defer store.Clear()
	if err := tracer.Start(tracer.WithAgentURL(agent.URL), tracer.WithSpanPool(true), tracer.WithLogStartup(false)); err != nil {
		t.Fatal(err)
	}
	defer tracer.Stop()

	// Trace A: background job span (no HTTP scope), finished normally.
	old := tracer.StartSpan("background.job")
	Finished(old) // woven Span.Finish hook
	old.Finish()
	// A goroutine that outlived the job still reports with the job ctx
	// (vulnerability.Report -> AnnotationForContext -> AnnotationFor).
	if variant == "negative-starve" {
		config.RequestSamplingPct = 0
	}
	stale := AnnotationFor(old)
	config.RequestSamplingPct = 100
	if stale.Sampled {
		stale.Lock()
		stale.AddVulnerability(model.NewVulnerability(constants.VulnerabilityTypeWeakHash, model.NewEvidenceString("MD5-from-trace-A"), &model.Location{SpanID: 1}))
		stale.Unlock()
	}

	// Trace B: a new HTTP request. Wait (bounded) until the pool hands back A's object.
	var recycled *tracer.Span
	deadline := time.Now().Add(10 * time.Second)
	attempts := 0
	for time.Now().Before(deadline) {
		tracer.Flush()
		runtime.Gosched()
		attempts++
		s := tracer.StartSpan("http.request")
		if s == old {
			recycled = s
			break
		}
		Finished(s)
		s.Finish()
	}
	if recycled == nil {
		t.Skipf("span pool did not recycle A's object within deadline (attempts=%d)", attempts)
	}
	_, scope, _ := request.Begin(context.Background())
	defer scope.Finish()
	ann := BindScope(recycled, scope)
	vulns := 0
	if ann != nil {
		ann.Lock()
		vulns = len(ann.Event.Vulnerabilities)
		ann.Unlock()
	}
	t.Logf("attempts=%d recycledSameObject=true newRootSpanID=%d scopeActive=%t BindScope==stale:%t staleSampled=%t vulnerabilitiesAlreadyOnNewRequest=%d",
		attempts, recycled.Context().SpanID(), scope.Active(), ann == stale, stale.Sampled, vulns)
	switch {
	case ann == stale && vulns > 0:
		t.Errorf("BUG (cross-request bleed): new request root inherited trace A's annotation carrying %d foreign finding(s)", vulns)
	case ann == nil && scope.Active():
		t.Errorf("BUG (false negative): active admitted request inherited trace A's negative decision; BindScope returned nil")
	}
	Finished(recycled)
	recycled.Finish()
}
