package store_test

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	wrappers "github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/redaction"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/stretchr/testify/require"
)

type f3ReviewRequest struct {
	scope *request.Scope
	span  *tracer.Span
	ann   *spans.Annotation
	query string
}

func TestIndependentF3SQLSnapshotRetention(t *testing.T) {
	const (
		eventCount       = 64
		findingsPerEvent = 64
		prefix           = "SELECT * FROM users WHERE id = "
		sourceValue      = "1 OR 1=1"
		suffix           = " AND name = 'alice'"
	)

	require.Equal(t, eventCount, config.MaxConcurrentRequests)
	require.Equal(t, findingsPerEvent, config.VulnerabilitiesPerRequest)
	require.Equal(t, uint64(250), config.TruncationMaxValue)
	require.True(t, config.RedactionEnabled)

	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	requests := make([]f3ReviewRequest, eventCount)
	finishRequests := func() {
		for index := range requests {
			state := &requests[index]
			if state.span != nil {
				spans.Finished(state.span)
				state.span.Finish()
			}
			if state.scope != nil {
				state.scope.Finish()
			}
			*state = f3ReviewRequest{}
		}
	}
	t.Cleanup(finishRequests)

	padding := strings.Repeat(" ", redaction.MaxAnalyzerBytes-len(prefix)-len(sourceValue)-len(suffix))
	for index := range requests {
		_, scope, created := request.Begin(context.Background())
		require.True(t, created)
		analysis, ok := scope.Analysis()
		require.True(t, ok)
		tainted, ok := analysis.TaintString(constants.OriginHttpRequestParameter, "id", sourceValue)
		require.True(t, ok)
		query := wrappers.StringsJoin([]string{prefix, tainted, suffix + padding}, "")
		require.Len(t, query, redaction.MaxAnalyzerBytes)

		span := tracer.StartSpan("independent-f3-review")
		annotation := spans.BindScope(span, scope)
		require.NotNil(t, annotation)
		requests[index] = f3ReviewRequest{scope: scope, span: span, ann: annotation, query: query}
	}

	before := f3ReviewHeapInuse()
	var pinnedPrefix uintptr
	for eventIndex := range requests {
		state := &requests[eventIndex]
		sqlAnalysis := redaction.AnalyzeSQL(state.query)
		require.Equal(t, redaction.AnalysisOK, sqlAnalysis.Status)
		require.NotEmpty(t, sqlAnalysis.Sensitive)
		for finding := 1; finding <= findingsPerEvent; finding++ {
			snapshot, status := evidence.CollectString(state.query, constants.VulnerabilityTypeSqlInjection)
			require.Equal(t, evidence.StatusCollected, status)
			converted, ok := redaction.BuildWithSensitive(snapshot, sqlAnalysis.Sensitive, false)
			require.True(t, ok)
			require.NotEmpty(t, converted.Parts)
			require.Equal(t, prefix, converted.Parts[0].Value)
			if eventIndex == 0 && finding == 1 {
				require.Equal(t, unsafe.StringData(snapshot.Value()), unsafe.StringData(converted.Parts[0].Value))
				pinnedPrefix = uintptr(unsafe.Pointer(unsafe.StringData(converted.Parts[0].Value)))
			}

			commit := spans.TaintedCommit{
				Vulnerability: model.Vulnerability{
					Type:     constants.VulnerabilityTypeSqlInjection,
					Hash:     int32(finding),
					Evidence: model.NewEvidenceTaintedValue(converted.Parts),
				},
				Sources: converted.Sources,
			}
			require.True(t, state.ann.TryCommitTainted(&commit, nil))
			snapshot = nil
			converted = redaction.Result{}
		}
	}
	after := f3ReviewHeapInuse()
	delta := after - before
	expectedPinned := int64(eventCount * findingsPerEvent * redaction.MaxAnalyzerBytes)
	require.Greater(t, delta, expectedPinned-(8<<20))
	require.Greater(t, delta, int64(24<<20))
	runtime.KeepAlive(requests)

	payload, err := spans.BuildLimitedPayload(&requests[0].ann.Event, spans.PayloadEncodingMsgpack)
	require.NoError(t, err)
	identityBytes := eventCount * (len("id") + len(sourceValue))
	t.Logf(
		"events=%d activeRequests=%d vulnerabilities=%d queryBytes=%d defaultTruncationCharacters=%d identityBytes=%d heapBefore=%d heapAfter=%d delta=%d wholeFeatureCeiling=%d ratio=%.2f pinnedPerEvent=%d pinnedPrefix=%t",
		eventCount, eventCount, eventCount*findingsPerEvent, redaction.MaxAnalyzerBytes,
		config.TruncationMaxValue, identityBytes, before, after, delta, 24<<20,
		float64(delta)/float64(24<<20), findingsPerEvent*redaction.MaxAnalyzerBytes, pinnedPrefix != 0,
	)
	t.Logf("eventSources=%d eventVulnerabilities=%d wireBytes=%d fallback=%t",
		len(requests[0].ann.Event.Sources), len(requests[0].ann.Event.Vulnerabilities),
		len(payload.Encoded), payload.Truncated)

	finishRequests()
	mock.Reset()
	finished := f3ReviewHeapInuse()
	t.Logf("finishedHeap=%d released=%d", finished, after-finished)
}

func f3ReviewHeapInuse() int64 {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return int64(stats.HeapInuse)
}
