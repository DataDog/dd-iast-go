package store_test

import (
	"context"
	"runtime"
	"strings"
	"testing"

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

//go:noinline
func reviewCommitCollected(t *testing.T, ann *spans.Annotation, query string, hash int32) {
	t.Helper()
	snapshot, status := evidence.CollectString(query, constants.VulnerabilityTypeSqlInjection)
	require.Equal(t, evidence.StatusCollected, status)
	analysis := redaction.AnalyzeSQL(query)
	require.Equal(t, redaction.AnalysisOK, analysis.Status)
	result, ok := redaction.BuildWithSensitive(snapshot, analysis.Sensitive, false)
	require.True(t, ok)
	require.Len(t, result.Parts, 2)
	require.Equal(t, "xx", result.Parts[0].Value)
	require.Len(t, result.Parts[1].Value, 248)
	commit := spans.TaintedCommit{
		Vulnerability: model.Vulnerability{
			Type: constants.VulnerabilityTypeSqlInjection, Hash: hash,
			Evidence: model.NewEvidenceTaintedValue(result.Parts),
		},
		Sources: result.Sources,
	}
	require.True(t, ann.TryCommitTainted(&commit, nil))
}

func TestBoundsEventEvidenceRetention(t *testing.T) {
	require.Equal(t, 64, config.MaxConcurrentRequests)
	require.Equal(t, 64, config.VulnerabilitiesPerRequest)
	require.Equal(t, uint64(250), config.TruncationMaxValue)
	require.True(t, config.RedactionEnabled)
	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	a, ok := scope.Analysis()
	require.True(t, ok)
	value, ok := a.TaintString(constants.OriginHttpRequestParameter, "q", "xx")
	require.True(t, ok)
	query := wrappers.StringsJoin([]string{value, strings.Repeat("z", redaction.MaxAnalyzerBytes-2)}, "")
	require.Len(t, query, redaction.MaxAnalyzerBytes)
	var roots [64]*tracer.Span
	var anns [64]*spans.Annotation
	for i := range roots {
		roots[i] = tracer.StartSpan("bounded-memory-review")
		anns[i] = spans.AnnotationFor(roots[i])
		require.True(t, anns[i].Sampled)
	}
	before := heapInuse()
	for _, ann := range anns {
		for hash := int32(1); hash <= 64; hash++ {
			reviewCommitCollected(t, ann, query, hash)
		}
	}
	retained := heapInuse()
	delta := int64(retained) - int64(before)
	require.Greater(t, delta, int64(64*64*redaction.MaxAnalyzerBytes)-(1<<20))
	t.Logf("events=%d vulnerabilities=%d charsPerEvidence=%d sourceIdentityBytes=%d rootCharge=%d heapBefore=%d heapAfter=%d delta=%d wholeFeatureCeiling=%d ratio=%.2f",
		len(anns), len(anns)*64, config.TruncationMaxValue, len(anns)*3,
		request.ActiveStore().ProcessCharged(), before, retained, delta, 24<<20, float64(delta)/float64(24<<20))
	payload, err := spans.BuildLimitedPayload(&anns[0].Event, spans.PayloadEncodingMsgpack)
	require.NoError(t, err)
	t.Logf("event wireBytes=%d fallback=%t retainedBackingBytesPerEvent=%d", len(payload.Encoded), payload.Truncated, 64*redaction.MaxAnalyzerBytes)
	for i, span := range roots {
		spans.Finished(span)
		span.Finish()
		anns[i] = nil
		roots[i] = nil
	}
	mock.Reset()
	scope.Finish()
	finished := heapInuse()
	t.Logf("events finished heap=%d released=%d", finished, int64(retained)-int64(finished))
	runtime.KeepAlive(ctx)
}
