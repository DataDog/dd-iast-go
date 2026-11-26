// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package suite

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/spans"
	iastreport "github.com/DataDog/dd-iast-go/internal/vulnerability"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/ext"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// checkSpanFinish checks that two rules work together on (*tracer.Span).Finish:
// the rule of dd-trace-go ("span_gls_finish"), which removes the span from the
// goroutine-local storage (GLS), and our rule ("span_finish"), which attaches
// the IAST event to the span. The order of the two injected statements is not
// defined (otelc #583), so the result must not depend on it: the setups import
// the rules in different orders.
//
//  1. The sink has no context. It finds the active span in the GLS (a feature of
//     dd-trace-go), and reports on this span: no orphan span is made.
//  2. When the span finishes, the IAST event is attached to it.
//  3. The span is no more in the GLS after Finish: the next sink makes an
//     orphan span.
func checkSpanFinish(t *testing.T) {
	requireInstrumented(t)

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	span, _ := tracer.StartSpanFromContext(context.Background(), "request")
	require.NotNil(t, span)

	// 1. The span is active in the GLS: from the sink, with no context.
	active, ok := tracer.SpanFromContext(context.Background())
	require.True(t, ok, "the GLS of dd-trace-go does not hold the active span")
	require.Equal(t, span.Context().SpanID(), active.Context().SpanID())

	digest := indirectCall1(md5.Sum, []byte("hello"))
	assert.Equal(t, md5Digest, digest[:])
	assert.Empty(t, mockTracer.FinishedSpans(), "the report must wait for the span; it must not make a span")

	// 2. The IAST event is attached when the span finishes.
	span.Finish()
	finished := mockTracer.FinishedSpans()
	require.Len(t, finished, 1)
	request := finished[0]
	require.Equal(t, "request", request.OperationName())
	assert.Equal(t, 1.0, request.Tag(spans.SpanTagEnabled))

	var event model.Event
	require.NoError(t, json.Unmarshal([]byte(request.Tag(spans.SpanTagJson).(string)), &event))
	require.Len(t, event.Vulnerabilities, 1)
	assert.Equal(t, constants.VulnerabilityTypeWeakHash, event.Vulnerabilities[0].Type)
	require.NotNil(t, event.Vulnerabilities[0].Location)
	assert.Equal(t, request.Context().SpanID(), event.Vulnerabilities[0].Location.SpanID)
	assert.Equal(t, pkgPath+".indirectCall1[...]", event.Vulnerabilities[0].Location.Method)

	// 3. The GLS no more holds the span, and the next sink makes an orphan span.
	_, ok = tracer.SpanFromContext(context.Background())
	assert.False(t, ok, "the GLS of dd-trace-go still holds a finished span")

	_ = indirectCall1(md5.Sum, []byte("hello"))
	finished = mockTracer.FinishedSpans()
	require.Len(t, finished, 2)
	assert.Equal(t, "vulnerability", finished[1].OperationName())
	assert.Equal(t, "vulnerability", finished[1].Tag(ext.SpanType))
}

// CheckLateReportAfterRootFinish checks the reports that come after the root
// span finished, with the real tracer, the Finish hook of the tool under test,
// and the production report path:
//
//  1. The payload of the first Finish has the finding of the first report.
//  2. Reports after the finish, started at the same time, make no annotation,
//     no finding, no span, and use no capacity; the counter of dropped reports
//     grows.
//  3. Two more calls of Finish at the same time do not change the payload.
func CheckLateReportAfterRootFinish(t *testing.T) {
	requireInstrumented(t)

	original := config.MaxConcurrentRequests
	config.MaxConcurrentRequests = 1
	t.Cleanup(func() { config.MaxConcurrentRequests = original })

	mockTracer := mocktracer.Start()
	t.Cleanup(mockTracer.Stop)

	root := tracer.StartSpan("request")
	child := root.StartChild("work")
	ctx := tracer.ContextWithSpan(context.Background(), child)

	var executed atomic.Uint64
	iastreport.Report(ctx, constants.VulnerabilityTypeWeakHash, "MD5", &executed)
	require.Equal(t, uint64(1), executed.Load())
	child.Finish()
	root.Finish()

	payload := func() string {
		finished := mockTracer.FinishedSpans()
		require.Len(t, finished, 2, "no span must be made by a late report")
		return finished[1].Tag(spans.SpanTagJson).(string)
	}
	first := payload()
	var event model.Event
	require.NoError(t, json.Unmarshal([]byte(first), &event))
	require.Len(t, event.Vulnerabilities, 1)
	assert.Equal(t, "MD5", event.Vulnerabilities[0].Evidence.Value)

	dropped := telemetry.DroppedReport.Load()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 8 {
		wg.Go(func() {
			<-start
			iastreport.Report(ctx, constants.VulnerabilityTypeWeakHash, fmt.Sprintf("SHA1-%d", i), &executed)
		})
	}
	for range 2 {
		wg.Go(func() {
			<-start
			root.Finish()
		})
	}
	close(start)
	wg.Wait()

	assert.Equal(t, uint64(1), executed.Load(), "a report after the finish was made")
	assert.Equal(t, first, payload(), "the payload changed after the first Finish")
	assert.Greater(t, telemetry.DroppedReport.Load(), dropped, "the dropped reports are not counted")
	assert.False(t, spans.AnnotationFor(child).Sampled, "a late report got an annotation")

	// No capacity is used (it is 1): another request is still analyzed.
	other := tracer.StartSpan("other")
	t.Cleanup(func() { other.Finish() })
	assert.True(t, spans.AnnotationFor(other).Sampled, "the late reports used capacity")
}
