// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build iast_g0test

package g0test_test

import (
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/stretchr/testify/require"
)

// TestMStateSkipsHook checks the two other conditions of the context check
// __dd_iast_ok: the hooks do not run while the M allocates (m.mallocing != 0)
// or while it disables preemption (m.preemptoff != ""). TestSystemStackSkipsHook
// checks the system stack (gp != m.curg) and the runtime locks (m.locks).
//
// No public API runs user code in these states, so a child process writes the
// fields of its own M (test only). The offsets of the fields come from DWARF
// data (see mFieldOffsets): the layout of runtime.m changes between Go
// versions.
//
//   - preemptoff: the child sets a reason, runs the hooked operations on
//     tainted heap inputs, and clears the reason. Without the condition, the
//     wrappers run (entries and tainted results).
//   - mallocing: the runtime must not allocate while mallocing is set (an
//     allocation sets mallocing again, and clears it at its end). The child
//     sets mallocing, runs the hooked operations on tainted heap inputs with
//     results in stack buffers (the original bodies do not allocate), checks
//     that mallocing is still set, and clears it. Without the condition, the
//     wrappers run (entries) and allocate their results (mallocing is then
//     0).
const mStateEnv = "DD_IAST_G0_MSTATE" // "<offset of mallocing>,<offset of preemptoff>"

// mStateWant is the number of wrapper calls of noAllocWork on a normal
// goroutine (the control): one for each operation.
const mStateWant = 6

func TestMStateSkipsHook(t *testing.T) {
	mallocing, preemptoff, err := mFieldOffsets(t)
	if errors.Is(err, exec.ErrNotFound) {
		t.Skipf("offsets of runtime.m fields: %v", err)
	}
	require.NoError(t, err, "offsets of runtime.m fields")
	// The original bodies of noAllocWork must not allocate: else an
	// allocation clears mallocing in the child, and the test fails also with
	// a correct hook. The inputs are not tainted here, so the hooks do not
	// run.
	inS, inB, inR := heapString("ms-tainted-12"), []byte(heapString("ms-bytes-123")), []rune("ms-runes-12")
	if n := testing.AllocsPerRun(20, func() { _ = noAllocWork(inS, inB, inR) }); n != 0 {
		t.Fatalf("noAllocWork allocates %v times without the hooks: the test needs results in stack buffers", n)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), fmt.Sprintf("%s=%d,%d", mStateEnv, mallocing, preemptoff), "GOTRACEBACK=single")
	b, err := cmd.CombinedOutput()
	out := string(b)
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, firstLines(out, 12))
	}
	var control, preempt, malloc uint64
	var preemptTainted, mallocKept bool
	parsed := false
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "MSTATE-OK ") {
			_, err := fmt.Sscanf(line, "MSTATE-OK control=%d preemptoff=%d preemptoff-tainted=%t mallocing=%d mallocing-kept=%t", &control, &preempt, &preemptTainted, &malloc, &mallocKept)
			parsed = err == nil
		}
	}
	if !parsed {
		if strings.Contains(out, "cannot taint") {
			if os.Getenv("DD_IAST_REQUIRE_WOVEN") == "1" {
				t.Fatalf("runtime is not woven (DD_IAST_REQUIRE_WOVEN=1):\n%s", out)
			}
			t.Skip("runtime is not woven: use `go tool orchestrion go test`")
		}
		t.Fatalf("no result line in the child output:\n%s", firstLines(out, 12))
	}
	t.Logf("child: control-entries=%d preemptoff-entries=%d (tainted: %t) mallocing-entries=%d (mallocing kept: %t)", control, preempt, preemptTainted, malloc, mallocKept)
	if control < mStateWant {
		t.Fatalf("the control on a normal goroutine did not enter the hooks: %d entries, want >= %d", control, mStateWant)
	}
	if preempt != 0 || preemptTainted {
		t.Errorf("hook ran while m.preemptoff != \"\" (%d entries, tainted result: %t)", preempt, preemptTainted)
	}
	if malloc != 0 || !mallocKept {
		t.Errorf("hook ran while m.mallocing != 0 (%d entries, an allocation cleared mallocing: %t)", malloc, !mallocKept)
	}
}

// noAllocWork runs the 6 hooked operations that can use a stack buffer, with
// results of at most 32 bytes (or 32 runes) that do not escape: the original
// bodies use the stack buffer and do not allocate. The writes to cb and sb
// make the compiler call the conversions (it does not copy a []byte that the
// code only reads).
//
//go:noinline
func noAllocWork(s string, b []byte, r []rune) int {
	c := s[:4] + s[4:]          // concatstrings (concatstring2)
	cb := []byte(s[:4] + s[4:]) // concatbytes (concatbyte2)
	cb[0] ^= 1
	bs := string(b) // slicebytetostring
	sb := []byte(s) // stringtoslicebyte
	sb[0] ^= 1
	rs := string(r) // slicerunetostring
	sr := []rune(s) // stringtoslicerune
	return int(c[1]) + int(cb[0]) + int(bs[1]) + int(sb[0]) + int(rs[1]) + int(sr[1])
}

// mStateChild is the child process of TestMStateSkipsHook.
func mStateChild(v string) int {
	a, b, ok := strings.Cut(v, ",")
	mallocing, err1 := strconv.ParseUint(a, 10, 32)
	preemptoff, err2 := strconv.ParseUint(b, 10, 32)
	if !ok || err1 != nil || err2 != nil {
		fmt.Println("bad", mStateEnv, v)
		return 3
	}
	inS := heapString("ms-tainted-12")
	inB := []byte(heapString("ms-bytes-123"))
	inR := []rune("ms-runes-12")
	taintedS = heapString("g0-tainted-value")
	taintedB = []byte(heapString("g0-tainted-bytes"))
	taintedR = make([]rune, 8)
	for i := range taintedR {
		taintedR[i] = 'r'
	}
	if !heapbits.SetString(inS) || !heapbits.SetBytes(inB) || !heapbits.Set(unsafe.Pointer(&inR[0]), uintptr(4*len(inR))) ||
		!heapbits.SetString(taintedS) || !heapbits.SetBytes(taintedB) || !heapbits.Set(unsafe.Pointer(&taintedR[0]), 32) || !heapbits.Live() {
		fmt.Println("cannot taint")
		return 3
	}
	type report struct {
		control, preempt, malloc uint64
		preemptTainted           bool
		mallocKept               bool
	}
	done := make(chan report)
	go func() {
		runtime.LockOSThread() // keep the M of this goroutine
		var r report
		mp := acquirem()
		releasem(mp)
		e0 := entries()
		_ = noAllocWork(inS, inB, inR) // control on a normal goroutine
		e1 := entries()
		r.control = e1 - e0

		po := (*string)(unsafe.Add(mp, preemptoff))
		*po = "iast-g0test"
		r.preemptTainted = heapWork()
		_ = noAllocWork(inS, inB, inR)
		*po = ""
		e2 := entries()
		r.preempt = e2 - e1

		mc := (*int32)(unsafe.Add(mp, mallocing))
		*mc = 1
		_ = noAllocWork(inS, inB, inR)
		r.mallocKept = *mc == 1 // no allocation cleared it
		*mc = 0
		r.malloc = entries() - e2
		done <- r
	}()
	r := <-done
	fmt.Printf("MSTATE-OK control=%d preemptoff=%d preemptoff-tainted=%t mallocing=%d mallocing-kept=%t\n", r.control, r.preempt, r.preemptTainted, r.malloc, r.mallocKept)
	return 0
}

// mFieldOffsets returns the offsets of the fields mallocing (int32) and
// preemptoff (string) of runtime.m. It reads the DWARF data of the test
// binary. go test removes this data (it links with -s -w unless -c or a
// profile flag is set): then it builds a small program with the same
// toolchain, and reads its DWARF data. The aspects do not change runtime.m,
// so the layout is the same.
func mFieldOffsets(t *testing.T) (mallocing, preemptoff uintptr, err error) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		return 0, 0, err
	}
	mallocing, preemptoff, err = dwarfMFields(exe)
	if err == nil {
		return mallocing, preemptoff, nil
	}
	t.Logf("no DWARF data in the test binary (%v): build a probe program", err)
	goCmd, lookErr := exec.LookPath("go")
	if lookErr != nil {
		return 0, 0, fmt.Errorf("no go command for the probe program: %w", lookErr)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\n\nimport \"runtime\"\n\nfunc main() { println(runtime.Version()) }\n"), 0o600); err != nil {
		return 0, 0, err
	}
	bin := filepath.Join(dir, "probe")
	cmd := exec.Command(goCmd, "build", "-o", bin, src)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=", "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
	if out, err := cmd.CombinedOutput(); err != nil {
		return 0, 0, fmt.Errorf("build the probe program: %w\n%s", err, out)
	}
	out, err := exec.Command(bin).CombinedOutput()
	if err != nil {
		return 0, 0, fmt.Errorf("run the probe program: %w\n%s", err, out)
	}
	if v := strings.TrimSpace(string(out)); v != runtime.Version() {
		return 0, 0, fmt.Errorf("the probe program uses %s, the test uses %s", v, runtime.Version())
	}
	return dwarfMFields(bin)
}

// dwarfMFields reads the offsets of runtime.m.mallocing and
// runtime.m.preemptoff in the DWARF data of the executable file path.
func dwarfMFields(path string) (mallocing, preemptoff uintptr, err error) {
	d, err := openDWARF(path)
	if err != nil {
		return 0, 0, err
	}
	want := map[string]struct {
		typ  string
		size int64
	}{
		"mallocing":  {"int32", 4},
		"preemptoff": {"string", int64(2 * unsafe.Sizeof(uintptr(0)))},
	}
	found := map[string]uintptr{}
	r := d.Reader()
	for {
		e, err := r.Next()
		if err != nil {
			return 0, 0, err
		}
		if e == nil {
			break
		}
		if e.Tag == dwarf.TagCompileUnit {
			continue // read the children
		}
		if e.Tag != dwarf.TagStructType || e.Val(dwarf.AttrName) != "runtime.m" {
			if e.Children {
				r.SkipChildren()
			}
			continue
		}
		for {
			c, err := r.Next()
			if err != nil {
				return 0, 0, err
			}
			if c == nil || c.Tag == 0 {
				break
			}
			name, _ := c.Val(dwarf.AttrName).(string)
			w, ok := want[name]
			if c.Tag != dwarf.TagMember || !ok {
				continue
			}
			off, ok1 := c.Val(dwarf.AttrDataMemberLoc).(int64)
			toff, ok2 := c.Val(dwarf.AttrType).(dwarf.Offset)
			if !ok1 || !ok2 {
				return 0, 0, fmt.Errorf("runtime.m.%s: no offset or type", name)
			}
			typ, err := d.Type(toff)
			if err != nil {
				return 0, 0, err
			}
			if dwarfName(typ) != w.typ || typ.Size() != w.size {
				return 0, 0, fmt.Errorf("runtime.m.%s: type %s (size %d), want %s (size %d)", name, typ, typ.Size(), w.typ, w.size)
			}
			found[name] = uintptr(off)
		}
		break
	}
	m, ok1 := found["mallocing"]
	p, ok2 := found["preemptoff"]
	if !ok1 || !ok2 {
		return 0, 0, fmt.Errorf("runtime.m fields not found in the DWARF data (found %v)", found)
	}
	return m, p, nil
}

func dwarfName(typ dwarf.Type) string {
	if st, ok := typ.(*dwarf.StructType); ok {
		return st.StructName
	}
	return typ.Common().Name
}

func openDWARF(path string) (*dwarf.Data, error) {
	if f, err := elf.Open(path); err == nil {
		defer f.Close()
		return f.DWARF()
	}
	if f, err := macho.Open(path); err == nil {
		defer f.Close()
		return f.DWARF()
	}
	if f, err := pe.Open(path); err == nil {
		defer f.Close()
		return f.DWARF()
	}
	return nil, fmt.Errorf("%s: not an ELF, Mach-O or PE file", path)
}
