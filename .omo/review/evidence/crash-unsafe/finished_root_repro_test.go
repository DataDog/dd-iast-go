package spans

import (
	"testing"
	"weak"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

func TestReproFinishedRootAcceptsReplacementFromLiveChild(t *testing.T) {
	previousSampling := config.RequestSamplingPct
	previousCapacity := config.MaxConcurrentRequests
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 2
	t.Cleanup(func() {
		config.RequestSamplingPct = previousSampling
		config.MaxConcurrentRequests = previousCapacity
	})

	mock := mocktracer.Start()
	t.Cleanup(mock.Stop)
	root := tracer.StartSpan("root")
	child := tracer.StartSpan("child", tracer.ChildOf(root.Context()))
	t.Cleanup(func() {
		Finished(root)
		child.Finish()
	})
	if child.Root() != root {
		t.Fatal("test tracer did not preserve the root relationship")
	}
	if child == root {
		t.Fatal("test tracer reused the root pointer for the child")
	}

	original := AnnotationFor(root)
	if original == nil || !original.Sampled {
		t.Fatal("root did not receive an initial sampled annotation")
	}
	Finished(root)
	if !original.Closed() {
		t.Fatal("root finish did not close the original annotation")
	}
	root.Finish()
	if child.Root() != root {
		t.Fatal("child lost the finished root relationship")
	}

	replacement := AnnotationFor(child)
	if replacement == nil || !replacement.Sampled {
		t.Fatal("live child did not receive a sampled annotation")
	}
	if replacement == original {
		t.Fatal("live child reused the closed root annotation")
	}
	if !replacement.Closed() {
		t.Error("live child recreated an open annotation for an already-finished root")
	}
	mapped, ok := store.Load(weak.Make(root))
	if !ok || mapped != replacement {
		t.Error("child replacement was not stored under the finished root key")
	}

	Finished(child)
	retained, ok := store.Load(weak.Make(root))
	if !ok || retained != replacement || retained.Closed() {
		t.Error("finishing the child did not leave the replacement under the finished root key")
	}
	t.Logf("post-child-finish root-key replacement retained=%t closed=%t", ok && retained == replacement, retained != nil && retained.Closed())
}
