// Copy to iast/io/zz_review_panic_test.go in an isolated repository copy.
package io_test

import (
	"io"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/iobridge"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/orchestrion/runtime/built"
)

func TestReview_InternalReaderCallbackCannotPanicHost(t *testing.T) {
	if !built.WithOrchestrion {
		t.Fatal("requires woven stdlib")
	}
	t.Cleanup(func() { iobridge.Register(request.PropagateReader, request.ReadAllBytes) })
	internalFault := &struct{ origin string }{"IAST reader callback"}
	iobridge.Register(func(any, any) { panic(internalFault) }, request.ReadAllBytes)
	var seen any
	func() {
		defer func() { seen = recover() }()
		reader := io.LimitReader(strings.NewReader("host"), 2)
		if reader == nil {
			t.Fatal("host result changed")
		}
	}()
	if seen != nil {
		t.Fatalf("IAST-only panic escaped io.LimitReader: type=%T value=%v identical=%t", seen, seen, seen == internalFault)
	}
}
