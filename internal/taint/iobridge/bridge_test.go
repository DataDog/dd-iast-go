// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package iobridge_test

import (
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/iobridge"
)

type token struct {
	index      uint8
	generation uint64
}

// recorder is a set of test callbacks. The tests of this package run one
// after the other, thus one global recorder is sufficient.
type recorder struct {
	mu         sync.Mutex
	propagated int
	shared     int
	joined     []int
	guarded    int
	retargets  []token
	adopted    bool
	owners     int
	readAlls   int
	panicOnce  atomic.Bool
}

func (r *recorder) callbacks() iobridge.Callbacks {
	return iobridge.Callbacks{
		Propagate: func(input, output any) {
			r.mu.Lock()
			defer r.mu.Unlock()
			if input != nil && output != nil {
				r.propagated++
			}
		},
		PropagateShared: func(any, any) { r.mu.Lock(); r.shared++; r.mu.Unlock() },
		PropagateJoin: func(inputs [iobridge.MaxJoinInputs]any, count int, output any) {
			r.mu.Lock()
			defer r.mu.Unlock()
			if inputs[0] != nil && output != nil {
				r.joined = append(r.joined, count)
			}
		},
		PropagateGuarded: func(any, any) { r.mu.Lock(); r.guarded++; r.mu.Unlock() },
		Retarget: func(index uint8, generation uint64) {
			if r.panicOnce.CompareAndSwap(true, false) {
				panic("retarget callback failure")
			}
			r.mu.Lock()
			defer r.mu.Unlock()
			r.retargets = append(r.retargets, token{index: index, generation: generation})
		},
		Owner: func(input any) iobridge.ReadToken {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.owners++
			if _, ok := input.(*int); !ok {
				return iobridge.ReadToken{}
			}
			return iobridge.ReadToken{Index: 1, Generation: 1, OK: true}
		},
		ReadAll: func(_ any, data []byte, token iobridge.ReadToken) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.readAlls++
			r.adopted = string(data) == "body" && token.OK && token.Index == 1 && token.Generation == 1
		},
	}
}

func (r *recorder) retargetCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.retargets)
}

func install(t *testing.T) *recorder {
	t.Helper()
	r := &recorder{}
	iobridge.Register(r.callbacks())
	t.Cleanup(func() {
		iobridge.ReleaseOwner(1, 1)
		iobridge.ReleaseOwner(2, 1)
		if count := iobridge.GuardCountForTest(); count != 0 {
			t.Errorf("guard count is %d after the test", count)
		}
		if entries := iobridge.GuardEntriesForTest(); entries != 0 {
			t.Errorf("%d guard slots are not empty after the test", entries)
		}
	})
	return r
}

func TestCallbacksCannotReplaceReadAllResult(t *testing.T) {
	r := install(t)
	input, output := new(int), new(int)
	iobridge.Propagate(input, output)
	if r.propagated != 1 {
		t.Fatal("propagation callback was not called")
	}
	data := []byte("body")
	pointer := unsafe.SliceData(data)
	iobridge.ReadAllEnd(iobridge.ReadAllBegin(input), input, data)
	if !r.adopted {
		t.Fatal("read-all callback was not called")
	}
	if pointer != unsafe.SliceData(data) || string(data) != "body" {
		t.Fatal("read-all callback changed its input slice")
	}
	iobridge.PropagateShared(input, output)
	iobridge.PropagateGuarded(input, output)
	iobridge.PropagateJoin([iobridge.MaxJoinInputs]any{input}, 9, output)
	if r.shared != 1 || r.guarded != 1 || !slices.Equal(r.joined, []int{9}) {
		t.Fatalf("callbacks: shared=%d guarded=%d joined=%v", r.shared, r.guarded, r.joined)
	}
}

func TestRegisterRejectsMissingCallback(t *testing.T) {
	r := install(t)
	callbacks := r.callbacks()
	callbacks.Retarget = nil
	iobridge.Register(callbacks)
	// The first complete set stays installed.
	iobridge.Propagate(new(int), new(int))
	if r.propagated != 1 {
		t.Fatal("an incomplete callback set replaced the installed set")
	}
}

func TestSame(t *testing.T) {
	type body struct{ buffer strings.Builder }
	value := &body{}
	uncomparable := func() {}
	for name, test := range map[string]struct {
		a, b any
		want bool
	}{
		"same pointer":              {a: value, b: value, want: true},
		"same address, other type":  {a: value, b: &value.buffer},
		"nil and nil":               {a: nil, b: nil, want: true},
		"nil and pointer":           {a: nil, b: value},
		"uncomparable dynamic type": {a: uncomparable, b: uncomparable, want: true},
		"uncomparable slices":       {a: []int{1}, b: []int{1}},
		"typed nil pointer and nil": {a: (*body)(nil), b: nil},
	} {
		if got := iobridge.Same(test.a, test.b); got != test.want {
			t.Errorf("%s: Same = %v, want %v", name, got, test.want)
		}
	}
}

func TestGuardDetectsRetarget(t *testing.T) {
	r := install(t)
	wrapper, input, other := new(int), new(int), new(int)
	if !iobridge.Guard(wrapper, input, 1, 1) {
		t.Fatal("Guard failed on an empty table")
	}
	if iobridge.Guard(wrapper, input, 1, 1) {
		t.Fatal("Guard added a second entry for the same wrapper")
	}
	if got := iobridge.GuardCountForTest(); got != 1 {
		t.Fatalf("guard count = %d, want 1", got)
	}
	for range 100 {
		iobridge.CheckRead(wrapper, input)
	}
	// Another reader with no guard is not changed.
	iobridge.CheckRead(other, nil)
	if r.retargetCount() != 0 {
		t.Fatal("a same-target Read set the retargeted bit")
	}
	iobridge.CheckRead(wrapper, other)
	if r.retargetCount() != 1 || r.retargets[0] != (token{index: 1, generation: 1}) {
		t.Fatalf("retargets = %v", r.retargets)
	}
	if got := iobridge.GuardCountForTest(); got != 0 {
		t.Fatalf("guard count = %d after the retarget, want 0", got)
	}
	// The guard is removed, thus a second retarget is not reported.
	iobridge.CheckRead(wrapper, other)
	if r.retargetCount() != 1 {
		t.Fatal("a removed guard reported a second retarget")
	}
}

func TestGuardNilTargetAndUncomparableTypes(t *testing.T) {
	r := install(t)
	wrapper := new(int)
	uncomparable := map[string]int{}
	if !iobridge.Guard(wrapper, uncomparable, 1, 1) {
		t.Fatal("Guard failed")
	}
	iobridge.CheckRead(wrapper, uncomparable)
	if r.retargetCount() != 0 {
		t.Fatal("the same uncomparable target is a retarget")
	}
	iobridge.CheckRead(wrapper, nil)
	if r.retargetCount() != 1 {
		t.Fatal("a nil target is not a retarget")
	}
	if iobridge.Guard(nil, nil, 1, 1) || iobridge.Guard((*int)(nil), nil, 1, 1) {
		t.Fatal("Guard accepted a nil wrapper")
	}
	iobridge.CheckRead(nil, nil)
	iobridge.Unguard(nil)
}

func TestRetargetCallbackPanicDoesNotEscape(t *testing.T) {
	r := install(t)
	wrapper, input := new(int), new(int)
	if !iobridge.Guard(wrapper, input, 1, 1) {
		t.Fatal("Guard failed")
	}
	t.Cleanup(iobridge.ResetRetargetLostForTest)
	if iobridge.RetargetLost() {
		t.Fatal("the lost bit is set before a failure")
	}
	// A callback that returns normally does not set the lost bit.
	iobridge.CheckRead(wrapper, new(int))
	if iobridge.RetargetLost() {
		t.Fatal("a normal retarget set the lost bit")
	}
	if !iobridge.Guard(wrapper, input, 1, 1) {
		t.Fatal("Guard failed")
	}
	r.panicOnce.Store(true)
	iobridge.CheckRead(wrapper, new(int))
	if got := iobridge.GuardCountForTest(); got != 0 {
		t.Fatalf("guard count = %d after a panic in the callback, want 0", got)
	}
	// Fail closed: the bit of the owner can be missing, thus the lost bit must
	// be set.
	if !iobridge.RetargetLost() {
		t.Fatal("a panic in the callback did not set the lost bit")
	}
}

func TestGuardProbeBoundAndRelease(t *testing.T) {
	install(t)
	// Find 5 wrappers with the same first probe slot. The fifth does not
	// get an entry.
	var wrappers []*[16]byte
	var keep [][16]byte
	for len(wrappers) < 5 {
		keep = make([][16]byte, 4096)
		wrappers = wrappers[:0]
		start := -1
		for i := range keep {
			slot := int((uintptr(unsafe.Pointer(&keep[i])) >> 4) % 128)
			if start < 0 {
				start = slot
			}
			if slot == start {
				wrappers = append(wrappers, &keep[i])
				if len(wrappers) == 5 {
					break
				}
			}
		}
	}
	input := new(int)
	for i, wrapper := range wrappers[:4] {
		if !iobridge.Guard(wrapper, input, 1, uint64(1+i%2)) {
			t.Fatalf("Guard %d failed", i)
		}
	}
	if iobridge.Guard(wrappers[4], input, 1, 1) {
		t.Fatal("Guard added an entry outside the probe window")
	}
	if got := iobridge.GuardCountForTest(); got != 4 {
		t.Fatalf("guard count = %d, want 4", got)
	}
	iobridge.Unguard(wrappers[0])
	if got := iobridge.GuardCountForTest(); got != 3 {
		t.Fatalf("guard count = %d after Unguard, want 3", got)
	}
	iobridge.ReleaseOwner(1, 2)
	if got := iobridge.GuardCountForTest(); got != 1 {
		t.Fatalf("guard count = %d after the release of one owner, want 1", got)
	}
	iobridge.ReleaseOwner(1, 1)
	if got := iobridge.GuardCountForTest(); got != 0 {
		t.Fatalf("guard count = %d after the release of all owners, want 0", got)
	}
	if entries := iobridge.GuardEntriesForTest(); entries != 0 {
		t.Fatalf("%d guard slots are not empty after the release of all owners", entries)
	}
	runtime.KeepAlive(keep)
}

func TestGuardConcurrentUse(t *testing.T) {
	install(t)
	var group sync.WaitGroup
	for worker := range 8 {
		group.Go(func() {
			input := new(int)
			for iteration := range 200 {
				wrapper := new([32]byte)
				generation := uint64(1 + worker%2)
				if iobridge.Guard(wrapper, input, 1, generation) {
					iobridge.CheckRead(wrapper, input)
					if iteration%3 == 0 {
						iobridge.CheckRead(wrapper, wrapper)
					}
					iobridge.Unguard(wrapper)
				}
				if iteration%50 == 0 {
					iobridge.ReleaseOwner(1, generation)
				}
			}
		})
	}
	group.Wait()
}

// TestGuardConcurrentSameWrapper checks that concurrent Guard calls for the
// same wrapper never leave two entries of it: at most one call returns true,
// and the table has one entry of the wrapper for each call that returned
// true. It is a stress test with no fixed order.
// TestGuardSameWrapperAfterDuplicateCheck checks the same invariant with a
// fixed order.
func TestGuardConcurrentSameWrapper(t *testing.T) {
	install(t)
	const workers = 8
	for iteration := range 2000 {
		wrapper := new([32]byte)
		var start, group sync.WaitGroup
		start.Add(1)
		var added atomic.Int32
		for worker := range workers {
			group.Go(func() {
				start.Wait()
				if iobridge.Guard(wrapper, new(int), 1, uint64(1+worker%2)) {
					added.Add(1)
				}
			})
		}
		start.Done()
		group.Wait()
		if entries := iobridge.GuardEntriesOfForTest(wrapper); added.Load() > 1 || int(added.Load()) != entries {
			t.Fatalf("iteration %d: %d calls returned true, the table has %d entries of the wrapper", iteration, added.Load(), entries)
		}
		iobridge.Unguard(wrapper)
	}
}

// TestGuardSameWrapperAfterDuplicateCheck checks the invariant of Guard with a
// fixed order: two calls for the same wrapper both pass the first duplicate
// check before one of them adds its entry. At most one call can return true,
// and the table must have one entry of the wrapper for each call that returned
// true.
func TestGuardSameWrapperAfterDuplicateCheck(t *testing.T) {
	install(t)
	var arrived sync.WaitGroup
	arrived.Add(2)
	restore := iobridge.SetGuardHookForTest(func() {
		// Each call waits here until both calls passed the first
		// duplicate check.
		arrived.Done()
		arrived.Wait()
	})
	t.Cleanup(restore)
	wrapper := new([32]byte)
	t.Cleanup(func() { iobridge.Unguard(wrapper) })
	var group sync.WaitGroup
	var added atomic.Int32
	for generation := range uint64(2) {
		group.Go(func() {
			if iobridge.Guard(wrapper, new(int), 1, generation+1) {
				added.Add(1)
			}
		})
	}
	group.Wait()
	restore()
	entries := iobridge.GuardEntriesOfForTest(wrapper)
	if added.Load() > 1 || int(added.Load()) != entries {
		t.Fatalf("%d calls returned true, the table has %d entries of the wrapper", added.Load(), entries)
	}
	// With no concurrent call, Guard adds the entry.
	iobridge.Unguard(wrapper)
	if !iobridge.Guard(wrapper, new(int), 1, 1) || iobridge.GuardEntriesOfForTest(wrapper) != 1 {
		t.Fatal("Guard with no concurrent call did not add one entry")
	}
}

func TestCheckReadDoesNotAllocate(t *testing.T) {
	install(t)
	wrapper, input, other := new(int), new(int), new(int)
	if allocations := testing.AllocsPerRun(100, func() { iobridge.CheckRead(other, input) }); allocations != 0 {
		t.Fatalf("CheckRead with no guard allocates %.1f times", allocations)
	}
	if !iobridge.Guard(wrapper, input, 1, 1) {
		t.Fatal("Guard failed")
	}
	if allocations := testing.AllocsPerRun(100, func() {
		iobridge.CheckRead(wrapper, input)
		iobridge.CheckRead(other, input)
	}); allocations != 0 {
		t.Fatalf("CheckRead with a live guard allocates %.1f times", allocations)
	}
	iobridge.Unguard(wrapper)
}

// TestBridgeDependencies checks the dependency rule of the bridge: io, bufio
// and net/http import iobridge, thus iobridge can import only sync/atomic,
// unsafe, and the runtime with its dependencies.
func TestBridgeDependencies(t *testing.T) {
	gotool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go command is not available")
	}
	list := func(pkg string) map[string]bool {
		t.Helper()
		output, err := exec.Command(gotool, "list", "-deps", pkg).Output()
		if err != nil {
			t.Fatalf("go list -deps %s: %v", pkg, err)
		}
		packages := map[string]bool{}
		for _, line := range strings.Fields(string(output)) {
			packages[line] = true
		}
		return packages
	}
	const bridgePackage = "github.com/DataDog/dd-iast-go/internal/taint/iobridge"
	runtimeDeps := list("runtime")
	allowed := map[string]bool{bridgePackage: true, "sync/atomic": true, "unsafe": true}
	for dependency := range list(bridgePackage) {
		if !allowed[dependency] && !runtimeDeps[dependency] {
			t.Errorf("iobridge depends on %s", dependency)
		}
	}
}

// TestReadAllEndWithTokenThatIsNotOK checks that ReadAllEnd returns at once
// when the token of ReadAllBegin is not OK, and ReadAllBegin and ReadAllEnd do
// not allocate.
func TestReadAllEndWithTokenThatIsNotOK(t *testing.T) {
	r := install(t)
	input := strings.NewReader("body")
	data := []byte("body")
	token := iobridge.ReadAllBegin(input)
	if token.OK || r.owners != 1 {
		t.Fatalf("ReadAllBegin: token %+v, %d owner calls", token, r.owners)
	}
	iobridge.ReadAllEnd(token, input, data)
	iobridge.ReadAllEnd(iobridge.ReadToken{}, new(int), data)
	if r.readAlls != 0 {
		t.Fatalf("ReadAllEnd called the read-all callback %d times with a token that is not OK", r.readAlls)
	}
	if allocations := testing.AllocsPerRun(100, func() {
		iobridge.ReadAllEnd(iobridge.ReadAllBegin(input), input, data)
	}); allocations != 0 {
		t.Fatalf("ReadAllBegin and ReadAllEnd allocate %.1f times", allocations)
	}
}
