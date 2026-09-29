// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package heapbits_test

import (
	"math/rand/v2"
	"os"
	"runtime"
	"strconv"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
)

// modelObject is a live heap object and its expected taint bits.
type modelObject struct {
	b    []byte
	bits []bool
}

// modelSizes gives tiny (< 16 B, pointer-free), small, and large objects.
var modelSizes = []int{1, 3, 8, 15, 16, 24, 48, 100, 500, 1024, 4096, 20000, 40000, 200 << 10, 1 << 20}

// Random model test: random operations (allocate, Set, Clear, Copy, drop,
// GC, and checks with Any, Next, NextClean) on live objects, compared with a
// model of the expected bits. The objects are held by the test, so they stay
// live; a new object must always be clean (this checks the dropped objects,
// whose memory is used again).
//
// HEAPBITS_MODEL_SEED and HEAPBITS_MODEL_OPS change the seed and the number
// of operations.
func TestRandomModel(t *testing.T) {
	need(t)
	seed := uint64(42)
	if v, err := strconv.ParseUint(os.Getenv("HEAPBITS_MODEL_SEED"), 10, 64); err == nil {
		seed = v
	}
	ops := 10000
	if v, err := strconv.Atoi(os.Getenv("HEAPBITS_MODEL_OPS")); err == nil {
		ops = v
	}
	if testing.Short() {
		ops /= 10
	}
	t.Logf("seed %d, %d operations (HEAPBITS_MODEL_SEED, HEAPBITS_MODEL_OPS)", seed, ops)
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))

	var objs []*modelObject
	randRange := func(o *modelObject) (int, int) {
		n := len(o.b)
		off := r.IntN(n)
		l := 1 + r.IntN(n-off)
		if r.IntN(4) != 0 && l > 300 {
			l = 1 + r.IntN(300) // mostly short ranges
		}
		return off, l
	}
	check := func(op int, o *modelObject) {
		t.Helper()
		// Compare the tainted ranges (Next/NextClean) with the model.
		n := uintptr(len(o.b))
		p := unsafe.Pointer(unsafe.SliceData(o.b))
		got := make([]bool, n)
		for off := heapbits.Next(p, n, 0); off < n; {
			end := heapbits.NextClean(p, n, off)
			if end <= off {
				t.Fatalf("op %d: NextClean(%d) = %d", op, off, end)
			}
			for i := off; i < end; i++ {
				got[i] = true
			}
			off = heapbits.Next(p, n, end)
		}
		for i := range got {
			if got[i] != o.bits[i] {
				t.Fatalf("op %d: object of %d bytes, byte %d: got %v, want %v (seed %d)", op, n, i, got[i], o.bits[i], seed)
			}
		}
		// Any on a random range.
		off, l := randRange(o)
		want := false
		for _, v := range o.bits[off : off+l] {
			want = want || v
		}
		if heapbits.AnyBytes(o.b[off:off+l]) != want {
			t.Fatalf("op %d: Any(%d, %d) = %v, want %v (seed %d)", op, off, l, !want, want, seed)
		}
	}
	alloc := func(op int) {
		size := modelSizes[r.IntN(len(modelSizes))]
		b := heapBytes(size)
		if heapbits.AnyBytes(b) {
			t.Fatalf("op %d: a new object of %d bytes has taint (seed %d)", op, size, seed)
		}
		objs = append(objs, &modelObject{b: b, bits: make([]bool, size)})
	}
	for range 32 {
		alloc(-1)
	}
	for op := range ops {
		if len(objs) == 0 {
			alloc(op)
			continue
		}
		o := objs[r.IntN(len(objs))]
		switch k := r.IntN(100); {
		case k < 15:
			alloc(op)
		case k < 40:
			off, l := randRange(o)
			if !heapbits.SetBytes(o.b[off : off+l]) {
				t.Fatalf("op %d: Set failed (seed %d)", op, seed)
			}
			for i := off; i < off+l; i++ {
				o.bits[i] = true
			}
		case k < 50:
			off, l := randRange(o)
			heapbits.ClearBytes(o.b[off : off+l])
			for i := off; i < off+l; i++ {
				o.bits[i] = false
			}
		case k < 62:
			// Copy between two live objects (maybe the same: overlap).
			src := objs[r.IntN(len(objs))]
			so, sl := randRange(src)
			do := r.IntN(len(o.b))
			if r.IntN(3) == 0 {
				// Overlap in the same object, at a small distance.
				src = o
				so, sl = randRange(o)
				do = min(max(so+r.IntN(201)-100, 0), len(o.b)-1)
			}
			l := min(sl, len(o.b)-do)
			if !heapbits.Copy(unsafe.Pointer(&o.b[do]), unsafe.Pointer(&src.b[so]), uintptr(l)) {
				t.Fatalf("op %d: Copy failed (seed %d)", op, seed)
			}
			tmp := append([]bool(nil), src.bits[so:so+l]...)
			copy(o.bits[do:do+l], tmp)
		case k < 72:
			// Drop an object: its memory is used again later.
			i := r.IntN(len(objs))
			objs[i] = objs[len(objs)-1]
			objs[len(objs)-1] = nil
			objs = objs[:len(objs)-1]
		case k < 74:
			runtime.GC()
		default:
			check(op, o)
		}
	}
	runtime.GC()
	for i, o := range objs {
		check(ops+i, o)
	}
}
