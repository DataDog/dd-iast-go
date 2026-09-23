package propagation

import (
	"bytes"
	"runtime"
	"testing"
	"unsafe"
)

func TestReviewBufferViewBackingWithInteriorSlice(t *testing.T) {
	backing := make([]byte, 160)
	buffer := bytes.NewBuffer(backing[13:113:141])
	buffer.Next(96)
	for _, step := range []struct {
		name string
		run  func()
	}{
		{name: "initial", run: func() {}},
		{name: "write", run: func() { _, _ = buffer.WriteString("attack") }},
		{name: "compact", run: func() { buffer.Grow(30) }},
		{name: "truncate", run: func() { buffer.Truncate(4) }},
		{name: "reset", run: func() { buffer.Reset() }},
	} {
		t.Run(step.name, func(t *testing.T) {
			step.run()
			view := bufferView(buffer)
			value := buffer.Bytes()
			if view.Capacity != uint32(buffer.Cap()) || view.Length != uint32(buffer.Len()) {
				t.Fatalf("view length/capacity %d/%d, buffer %d/%d", view.Length, view.Capacity, buffer.Len(), buffer.Cap())
			}
			if cap(value) > 0 {
				base := uintptr(unsafe.Pointer(&backing[13]))
				if view.Anchor != unsafe.SliceData(value) || view.Backing != base ||
					view.Backing+uintptr(buffer.Cap()-cap(value)) != uintptr(unsafe.Pointer(view.Anchor)) {
					t.Fatalf("anchor/backing inconsistent: %+v, cap(view)=%d", view, cap(value))
				}
			}
			runtime.KeepAlive(buffer)
		})
	}
}
