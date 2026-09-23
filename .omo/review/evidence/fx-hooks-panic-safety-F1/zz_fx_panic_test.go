// Phase-3 verifier reproducer for hooks-panic-safety-F1 (not for commit).
package io_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/iobridge"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

type fxFault struct{ where string }

func fxCatch(f func()) (seen any) {
	defer func() { seen = recover() }()
	f()
	return nil
}

type fxPanicReader struct{ v any }

func (r *fxPanicReader) Read([]byte) (int, error) { panic(r.v) }

// Part A: fault injection through each iobridge entry point.
func TestFX_FaultInjection(t *testing.T) {
	if !built.WithOrchestrion {
		t.Fatal("requires woven stdlib")
	}
	t.Cleanup(func() { iobridge.Register(request.PropagateReader, request.ReadAllBytes) })
	propFault := &fxFault{"propagate"}
	readAllFault := &fxFault{"readAll"}
	iobridge.Register(func(any, any) { panic(propFault) }, func(any, []byte) { panic(readAllFault) })

	cases := []struct {
		name string
		call func()
	}{
		{"io.LimitReader", func() { _ = io.LimitReader(strings.NewReader("host"), 2) }},
		{"io.TeeReader", func() { _ = io.TeeReader(strings.NewReader("host"), io.Discard) }},
		{"io.MultiReader", func() { _ = io.MultiReader(strings.NewReader("host")) }},
		{"io.ReadAll", func() { _, _ = io.ReadAll(strings.NewReader("host")) }},
	}
	for _, c := range cases {
		seen := fxCatch(c.call)
		t.Logf("FAULT %-15s escaped=%t value=%v", c.name, seen != nil, seen)
	}
	// Host panic in flight inside io.ReadAll: the deferred IAST fault replaces it.
	hostFault := &fxFault{"host reader"}
	seen := fxCatch(func() { _, _ = io.ReadAll(&fxPanicReader{hostFault}) })
	t.Logf("FAULT io.ReadAll(host panics) recovered=%v hostPreserved=%t", seen, seen == hostFault)
}

type zeroReader struct{}

func (*zeroReader) Read([]byte) (int, error) { return 0, io.EOF }

type funcReader func([]byte) (int, error)

func (f funcReader) Read(p []byte) (int, error) { return f(p) }

type valueReader struct{ s string }

func (valueReader) Read([]byte) (int, error) { return 0, io.EOF }

type mapReader map[int]int

func (mapReader) Read([]byte) (int, error) { return 0, io.EOF }

// Part B: real registered callbacks, adversarial but valid customer inputs.
func TestFX_NaturalInputsNoIASTPanic(t *testing.T) {
	if !built.WithOrchestrion {
		t.Fatal("requires woven stdlib")
	}
	ctx, scope := activeContext(t)
	body := strings.NewReader("request-body-value")
	if !request.BindReader(ctx, body) {
		t.Fatal("bind failed")
	}
	var typedNil *strings.Reader
	big := bytes.Repeat([]byte("x"), store.MaxRootBytes+10)
	hostFault := &fxFault{"host"}
	inputs := []struct {
		name string
		call func() any
	}{
		{"LimitReader(bound)", func() any { r, _ := io.ReadAll(io.LimitReader(body, 7)); return r }},
		{"LimitReader(typedNil)", func() any { return io.LimitReader(typedNil, 1) }},
		{"LimitReader(nilIface)", func() any { return io.LimitReader(nil, 1) }},
		{"LimitReader(zeroSize)", func() any { return io.LimitReader(&zeroReader{}, 1) }},
		{"LimitReader(func)", func() any { return io.LimitReader(funcReader(func([]byte) (int, error) { return 0, io.EOF }), 1) }},
		{"LimitReader(value)", func() any { return io.LimitReader(valueReader{"v"}, 1) }},
		{"LimitReader(map)", func() any { return io.LimitReader(mapReader{}, 1) }},
		{"LimitReader(negative)", func() any { return io.LimitReader(body, -5) }},
		{"TeeReader(nil,nil)", func() any { return io.TeeReader(nil, nil) }},
		{"MultiReader(none)", func() any { return io.MultiReader() }},
		{"MultiReader(20 mixed)", func() any {
			rs := make([]io.Reader, 20)
			for i := range rs {
				switch i % 4 {
				case 0:
					rs[i] = body
				case 1:
					rs[i] = typedNil
				case 2:
					rs[i] = nil
				default:
					rs[i] = &zeroReader{}
				}
			}
			return io.MultiReader(rs...)
		}},
		{"ReadAll(oversized)", func() any { r, _ := io.ReadAll(bytes.NewReader(big)); return len(r) }},
		{"ReadAll(empty)", func() any { r, _ := io.ReadAll(strings.NewReader("")); return r }},
	}
	for _, in := range inputs {
		seen := fxCatch(func() { _ = in.call() })
		t.Logf("NATURAL %-24s panic=%v", in.name, seen)
		if seen != nil {
			t.Errorf("natural input %s panicked: %v", in.name, seen)
		}
	}
	// Host panic identity with real callbacks.
	seen := fxCatch(func() { _, _ = io.ReadAll(&fxPanicReader{hostFault}) })
	t.Logf("NATURAL ReadAll(host panics) hostPreserved=%t", seen == hostFault)
	if seen != hostFault {
		t.Errorf("host panic changed: %v", seen)
	}

	// Concurrency: readers derived from a bound body while the scope finishes.
	var wg sync.WaitGroup
	var mu sync.Mutex
	var panics []any
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				if p := fxCatch(func() {
					lr := io.LimitReader(body, 3)
					_ = io.MultiReader(lr, io.TeeReader(lr, io.Discard))
					_, _ = io.ReadAll(io.LimitReader(lr, 2))
				}); p != nil {
					mu.Lock()
					panics = append(panics, p)
					mu.Unlock()
				}
			}
		}()
	}
	scope.Finish()
	wg.Wait()
	t.Logf("NATURAL concurrent-with-Finish panics=%d", len(panics))
	if len(panics) != 0 {
		t.Errorf("concurrent panics: %v", panics[0])
	}
}

// Part C: realistic HTTP surface with real callbacks.
func TestFX_HTTPHandlerReaders(t *testing.T) {
	if !built.WithOrchestrion {
		t.Fatal("requires woven stdlib")
	}
	activeContext(t) // enables config for sampling
	var handlerPanic any
	tainted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerPanic = fxCatch(func() {
			lr := io.LimitReader(r.Body, 1<<20)
			mr := io.MultiReader(lr, strings.NewReader("-suffix"))
			data, _ := io.ReadAll(io.TeeReader(mr, io.Discard))
			tainted = taint.IsTaintedBytes(data)
			fmt.Fprint(w, len(data))
		})
	}))
	defer srv.Close()
	resp, err := http.Post(srv.URL, "text/plain", strings.NewReader("payload-from-client"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("HTTP response=%s handlerPanic=%v bodyTainted=%t", b, handlerPanic, tainted)
	if handlerPanic != nil {
		t.Errorf("handler panic: %v", handlerPanic)
	}
}
