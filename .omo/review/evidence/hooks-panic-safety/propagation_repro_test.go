// Copy to iast/propagation/zz_review_panic_test.go in an isolated repository copy.
package propagation_test

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/writerbridge"
	"github.com/DataDog/dd-iast-go/taint"
)

func reviewPanic(fn func()) (caught any) {
	defer func() { caught = recover() }()
	fn()
	return nil
}

func TestReview_NativePanicsPreserveIdentity(t *testing.T) {
	active := activeString(t, "attack")
	var original strings.Builder
	original.WriteString("seed")
	badCopy := original
	for _, tc := range []struct {
		name    string
		native  func()
		wrapped func()
	}{
		{"strings.Repeat", func() { strings.Repeat(active, -1) }, func() { propagation.StringsRepeat(active, -1) }},
		{"bytes.Repeat", func() { bytes.Repeat([]byte(active), -1) }, func() { propagation.BytesRepeat([]byte(active), -1) }},
		{"Builder copy", func() { badCopy.WriteString("z") }, func() { propagation.BuilderWriteString(&badCopy, "z") }},
		{"Buffer.Truncate", func() { var b bytes.Buffer; b.WriteString(active); b.Truncate(-1) }, func() {
			var b bytes.Buffer
			propagation.BufferWriteString(&b, active)
			propagation.BufferTruncate(&b, -1)
		}},
		{"string slice", func() { _ = active[:len(active)+1] }, func() { propagation.StringSliceHigh(active, len(active)+1) }},
		{"byte slice", func() { _ = []byte(active)[:len(active)+1] }, func() { propagation.BytesSliceHigh([]byte(active), len(active)+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, got := reviewPanic(tc.native), reviewPanic(tc.wrapped)
			if want == nil || reflect.TypeOf(want) != reflect.TypeOf(got) || !reflect.DeepEqual(want, got) {
				t.Fatalf("panic mismatch: native=%T %v, wrapped=%T %v", want, want, got, got)
			}
		})
	}
}

func TestReview_BufferTruncatePanicLeavesTaintAndExpectation(t *testing.T) {
	active := activeString(t, "attack")
	var buffer bytes.Buffer
	if _, err := propagation.BufferWriteString(&buffer, active); err != nil {
		t.Fatal(err)
	}
	want := reviewPanic(func() { buffer.Truncate(-1) })
	got := reviewPanic(func() { propagation.BufferTruncate(&buffer, -1) })
	if reflect.TypeOf(want) != reflect.TypeOf(got) || !reflect.DeepEqual(want, got) {
		t.Fatalf("changed panic: native=%T %v wrapped=%T %v", want, want, got, got)
	}
	if !taint.IsTaintedString(propagation.BufferString(&buffer)) {
		t.Fatal("failed truncate lost existing writer provenance")
	}
	if _, err := propagation.BufferWriteString(&buffer, "!"); err != nil {
		t.Fatal(err)
	}
	if !taint.IsTaintedString(propagation.BufferString(&buffer)) {
		t.Fatal("failed truncate left writer state inconsistent for next write")
	}
}

func TestReview_InternalBufferInvalidationCannotPanicHost(t *testing.T) {
	active := activeString(t, "attack")
	var buffer bytes.Buffer
	if _, err := propagation.BufferWriteString(&buffer, active); err != nil {
		t.Fatal(err)
	}
	internalFault := &struct{ origin string }{"IAST native writer invalidation"}
	writerbridge.Register(func(uintptr, uintptr, uintptr, bool) { panic(internalFault) })
	var caught any
	func() {
		defer func() { caught = recover() }()
		_, _ = buffer.WriteString("host")
	}()
	writerbridge.Register(func(pointer, backing, capacity uintptr, preserve bool) {
		if s := request.ActiveStore(); s != nil {
			s.InvalidateBuffer(pointer, backing, capacity, preserve)
		}
	})
	if caught != nil {
		t.Fatalf("IAST-only panic escaped bytes.Buffer.WriteString: type=%T value=%v identical=%t", caught, caught, caught == internalFault)
	}
}
