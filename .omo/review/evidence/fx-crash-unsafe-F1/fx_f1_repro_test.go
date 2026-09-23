// Independent reproducer for phase-2 finding crash-unsafe-F1, written by the
// phase-3 verifier (node fx-crash-unsafe-F1). Not part of the upstream test
// suite.
package spans

import (
	"runtime"
	"testing"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

// TestFXLiveChildRecreatesOpenAnnotationAfterRootFinish reproduces the claimed
// mechanism through the package-internal API, using the same functions the
// woven tracer.Span.Finish hook and the reporting path call: Finished(root)
// (what the woven root.Finish prepends), then AnnotationFor(child) for a live
// child of that already-finished root.
func TestFXLiveChildRecreatesOpenAnnotationAfterRootFinish(t *testing.T) {
	prevSampling, prevCap := config.RequestSamplingPct, config.MaxConcurrentRequests
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 2
	t.Cleanup(func() {
		config.RequestSamplingPct = prevSampling
		config.MaxConcurrentRequests = prevCap
		store.Clear()
	})
	store.Clear()

	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)

	root := tracer.StartSpan("root")
	child := tracer.StartSpan("child", tracer.ChildOf(root.Context()))
	t.Cleanup(func() { child.Finish() })

	original := AnnotationFor(root)
	if original == nil || !original.Sampled {
		t.Fatal("root did not receive an initial sampled annotation")
	}

	// What the woven tracer.Span.Finish does for the root, in order.
	Finished(root)
	root.Finish()
	if !original.Closed() {
		t.Fatal("root finish did not close the original annotation")
	}
	if _, ok := store.Load(weak.Make(root)); ok {
		t.Fatal("root finish did not delete the root-keyed annotation")
	}

	// A live child of the finished root asks for an annotation.
	replacement := AnnotationFor(child)
	if replacement == nil || !replacement.Sampled {
		t.Fatal("live child did not receive a sampled annotation")
	}
	if replacement == original {
		t.Fatal("live child reused the closed root annotation")
	}
	if replacement.Closed() {
		t.Error("live child recreated an OPEN annotation for an already-finished root")
	}
	mapped, ok := store.Load(weak.Make(root))
	if !ok || mapped != replacement {
		t.Error("child replacement was not stored under the finished root key")
	}

	// A finding committed to the replacement is never emitted: the root has no
	// second finish hook, and the child's finish hook uses the child key.
	vuln := model.NewVulnerability(
		constants.VulnerabilityTypeWeakHash,
		model.NewEvidenceString("MD5"),
		nil,
	)
	commit := &TaintedCommit{Vulnerability: vuln}
	if !replacement.TryCommitTainted(commit, nil) {
		t.Fatal("committing a finding to the replacement failed")
	}

	Finished(child)
	child.Finish()

	stranded, ok := store.Load(weak.Make(root))
	if !ok || stranded != replacement || stranded.Closed() {
		t.Error("finishing the child did not leave the replacement open under the finished root key")
	}
	if len(stranded.Event.Vulnerabilities) != 1 {
		t.Fatalf("stranded vulnerabilities = %d, want 1", len(stranded.Event.Vulnerabilities))
	}
	for _, s := range mock.FinishedSpans() {
		if s.Tag(SpanTagJson) != nil || s.Tag(SpanTagMetaStruct) != nil {
			t.Errorf("span %v unexpectedly carries an IAST payload; the finding was emitted",
				s.OperationName())
		}
	}
	t.Logf("finding stranded: root-key replacement retained=%t closed=%t vulns=%d",
		ok && stranded == replacement, stranded.Closed(), len(stranded.Event.Vulnerabilities))

	runtime.KeepAlive(root)
	runtime.KeepAlive(child)
}

// TestFXFinishedRootReplacementLeaksAdmissionSlot shows the customer-visible
// consequence: replacement annotations retained under finished root keys
// cannot be trimmed while any span of that trace is alive, so they consume
// admission slots until MaxConcurrentRequests is exhausted and new requests
// are denied IAST analysis ("max concurrent requests reached").
func TestFXFinishedRootReplacementLeaksAdmissionSlot(t *testing.T) {
	prevSampling, prevCap := config.RequestSamplingPct, config.MaxConcurrentRequests
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 2
	t.Cleanup(func() {
		config.RequestSamplingPct = prevSampling
		config.MaxConcurrentRequests = prevCap
		store.Clear()
	})
	store.Clear()

	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)

	// Positive control: with an empty map a fresh root gets a sampled
	// annotation even though the map is at its high-water trim threshold.
	control := tracer.StartSpan("control")
	if ann := AnnotationFor(control); ann == nil || !ann.Sampled {
		t.Fatal("positive control: fresh root was not sampled with an empty map")
	}
	Finished(control)
	control.Finish()

	// Two finished roots, each retained by a live child that recreated an
	// annotation under the finished root key.
	var children []*tracer.Span
	for range 2 {
		root := tracer.StartSpan("root")
		child := tracer.StartSpan("child", tracer.ChildOf(root.Context()))
		Finished(root)
		root.Finish()
		if ann := AnnotationFor(child); ann == nil || !ann.Sampled {
			t.Fatal("replacement under finished root was not sampled")
		}
		children = append(children, child)
	}
	if size := store.Size(); size != 2 {
		t.Fatalf("map size = %d, want 2 retained replacements", size)
	}

	// Fresh request under 100% sampling: both admission slots are held by
	// dead-but-retained keys, trimStore cannot reclaim them, and the request
	// is dropped from IAST analysis.
	fresh := tracer.StartSpan("fresh.request")
	ann := AnnotationFor(fresh)
	if ann == nil || ann.Sampled {
		t.Fatal("fresh request was admitted although all admission slots are held by finished roots")
	}
	if ann != nonSampledAnnotation {
		t.Fatal("fresh request did not fall back to the non-sampled sentinel")
	}
	if size := store.Size(); size != 2 {
		t.Fatalf("map size = %d, want the fresh request to be dropped, not stored", size)
	}
	t.Log("fresh request denied IAST analysis: max concurrent requests reached (leaked slots)")

	fresh.Finish()
	for _, child := range children {
		runtime.KeepAlive(child)
	}
}
