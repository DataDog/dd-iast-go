//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:1:1
package reviewoperators

import (
	"context"
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:6
	"os"
	"reflect"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	native "github.com/DataDog/dd-iast-go/internal/reviewoperatornative"
	"github.com/DataDog/dd-iast-go/internal/taint/operatorbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
//line <generated>:1
	__orchestrion_iastprop "github.com/DataDog/dd-iast-go/iast/propagation"
)

//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:18
type namedString string
type namedBytes []byte
type namedIndex uint16

const folded = "a" + "b"
const foldedSize = len("ab" + "cd")

var constantArray [foldedSize]byte

func genericConcat[T ~string](a, b T) T {
	return __orchestrion_iastprop. //line <generated>:1
					Concat3(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:26
			a, ("x" + "y"), b)
}
func genericSlice[T ~string, I ~uint16](s T, lo I) T {
	return __orchestrion_iastprop. //line <generated>:1
					StringSliceLow(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:27
			s, lo)
}
func genericBytes[T ~[]byte](s T) T {
	return __orchestrion_iastprop. //line <generated>:1
					BytesSliceFull(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:28
			s, 1, 3, 4)
}
func genericConvert[S ~string, B ~[]byte](b B) S {
	return S( //line <generated>:1
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:29

//line <generated>:1
		__orchestrion_iastprop.BytesToString(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:29
			b))
}

func TestWeavingPreflight(t *testing.T) {
	want := os.Getenv("REVIEW_WOVEN") == "1"
	if built.WithOrchestrion != want {
		t.Fatalf("woven=%v want=%v", built.WithOrchestrion, want)
	}
	t.Logf("woven=%v", built.WithOrchestrion)
}

func TestEvaluationOrderAndTypes(t *testing.T) {
	var order []int
	f := func(i int, value string) string {
		order = append(order, i)
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:39
		return value
	}
	got :=
//line <generated>:1
		__orchestrion_iastprop.Concat3(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:40
			f(1, "a"), f(2, "b"), f(3, "c"))
	if got != "abc" || !reflect.DeepEqual(order, []int{1, 2, 3}) {
		t.Fatalf("%q %v", got, order)
	}
	order = nil
	base := func() []byte {
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:43
		order = append(order, 1)
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:43
		return []byte("abcdef")
	}
	idx := func(i int, v uint16) uint16 {
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:44
		order = append(order, i)
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:44
		return v
	}
	b :=
//line <generated>:1
		__orchestrion_iastprop.BytesSliceFull(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:45
			base(), idx(2, 1), idx(3, 4), idx(4, 5))
	if string(b) != "bcd" || cap(b) != 4 || !reflect.DeepEqual(order, []int{1, 2, 3, 4}) {
		t.Fatalf("%q cap=%d order=%v", b, cap(b), order)
	}
	if v := genericConcat(namedString("a"), namedString("b")); v != "axyb" {
		t.Fatal(v)
	}
	if v := genericSlice(namedString("abcd"), namedIndex(1)); v != "bcd" {
		t.Fatal(v)
	}
	if v := genericBytes(namedBytes("abcd")); string(v) != "bc" || cap(v) != 3 {
		t.Fatal(v)
	}
	if v := genericConvert[namedString](namedBytes("abcd")); v != "abcd" {
		t.Fatal(v)
	}
	switch "ab" {
	case "a" + "b":
	default:
		t.Fatal("constant switch")
	}
	if folded != "ab" || len(constantArray) != 4 {
		t.Fatal("constant folding")
	}
}

func capture(f func()) (out string) {
	defer func() {
		if p := recover(); p != nil {
			out = __orchestrion_iastprop.FmtSprintf("%T: %v", p, p)
		}
	}()
	f()
	return ""
}

func TestSlicePanicParity(t *testing.T) {
	s, b := "abcd", []byte("abcd")
	for _, bounds := range []struct {
		low  int64
		high uint64
		max  uint32
	}{
		{-1, 2, 3}, {0, 5, 6}, {3, 2, 4}, {1, 3, 2}, {1, 3, 9}, {0, ^uint64(0), 4}, {9, 10, 4},
	} {
		t.Run(__orchestrion_iastprop.FmtSprint(bounds), func(t *testing.T) {
			cases := []struct {
				name            string
				woven, baseline func()
			}{
				{"string", func() {
					_ =
//line <generated>:1
						__orchestrion_iastprop.StringSliceBounds(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:73
							s, bounds.low, bounds.high)
				}, func() { _ = native.StringBounds(s, bounds.low, bounds.high) }},
				{"bytes", func() {
					_ =
//line <generated>:1
						__orchestrion_iastprop.BytesSliceBounds(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:74
							b, bounds.low, bounds.high)
				}, func() { _ = native.BytesBounds(b, bounds.low, bounds.high) }},
				{"full", func() {
					_ =
//line <generated>:1
						__orchestrion_iastprop.BytesSliceFull(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:75
							b, bounds.low, bounds.high, bounds.max)
				}, func() { _ = native.BytesFull(b, bounds.low, bounds.high, bounds.max) }},
				{"low", func() {
					_ =
//line <generated>:1
						__orchestrion_iastprop.StringSliceLow(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:76
							s, bounds.high)
				}, func() { _ = native.StringLow(s, bounds.high) }},
				{"zero", func() {
					_ =
//line <generated>:1
						__orchestrion_iastprop.BytesSliceFullZero(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:77
							b, bounds.high, bounds.max)
				}, func() { _ = native.BytesFullZero(b, bounds.high, bounds.max) }},
			}
			for _, c := range cases {
				got, want := capture(c.woven), capture(c.baseline)
				if got != want {
					t.Errorf("%s got=%q want=%q", c.name, got, want)
				}
				t.Logf("%s: %s", c.name, got)
			}
		})
	}
}

func TestUnevaluatedArrayOperands(t *testing.T) {
	for _, rangeCase := range []bool{false, true} {
		t.Run(__orchestrion_iastprop.FmtSprint("range=", rangeCase), func(t *testing.T) {
			s, high, got := "abc", 99, 0
			panicText := capture(func() {
				if rangeCase {
					for range [1]string{
//line <generated>:1
						__orchestrion_iastprop.StringSliceHigh(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:94
							s, high)} {
						got++
					}
				} else {
					got = len([1]string{
//line <generated>:1
						__orchestrion_iastprop.StringSliceHigh(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:95
							s, high)})
				}
			})
			want := native.UnevaluatedLen(s, high)
			if rangeCase {
				want = native.UnevaluatedRange(s, high)
			}
			t.Logf("got=%d want=%d panic=%q", got, want, panicText)
			if panicText != "" || got != want {
				t.Errorf("previously unevaluated array operand was evaluated")
			}
		})
	}
}

var intSink int
var boolSink bool

func TestInactiveAllocations(t *testing.T) {
	if operatorbridge.HasValues() {
		t.Fatal("expected inactive operator gate")
	}
	a, b := "abc", "def"
	data := []byte("abcdef")
	m := map[string]int{"abcdef": 7}
	cases := []struct {
		name            string
		woven, baseline func()
	}{
		{"concat_len", func() {
			intSink = len(
//line <generated>:1
				__orchestrion_iastprop.Concat2(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:114
					a, b))
		}, func() { intSink = native.LenConcat(a, b) }},
		{"concat_compare", func() {
			boolSink =
//line <generated>:1
				__orchestrion_iastprop.Concat2(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:115
					a, b) == "abcdef"
		}, func() { boolSink = native.CompareConcat(a, b) }},
		{"conversion_local", func() {
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:116
			s :=
//line <generated>:1
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:116
				string(
//line <generated>:1
					__orchestrion_iastprop.BytesToString(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:116
						data))
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:116
			intSink = len(s)
		}, func() { intSink = native.LenConversion(data) }},
		{"conversion_compare_excluded", func() { boolSink = string(data) == "abcdef" }, func() { boolSink = native.CompareConversion(data) }},
		{"conversion_map_excluded", func() { intSink = m[string(data)] }, func() { intSink = native.MapConversion(m, data) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := testing.AllocsPerRun(100, c.baseline)
			got := testing.AllocsPerRun(100, c.woven)
			t.Logf("native=%.0f woven=%.0f allocations/op", want, got)
			if got != want {
				t.Errorf("inactive instrumentation adds heap allocation")
			}
		})
	}
}

func TestExactProvenanceAndCleanControls(t *testing.T) {
	if !built.WithOrchestrion {
		return
	}
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	ctx, _, created := request.Begin(context.Background())
	if !created {
		t.Fatal("scope not created")
	}
	defer request.FinishContext(ctx, true)
	source := taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "q"}
	s := taint.TaintString(ctx, source, "abcd")
	data := taint.TaintBytes(ctx, source, []byte("abcd"))
	if !taint.IsTaintedString(s) || !taint.IsTaintedBytes(data) {
		t.Fatal("source not tainted")
	}
	window :=
//line <generated>:1
		__orchestrion_iastprop.StringSliceBounds(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:140
			s, 1, 3)
	concat :=
//line <generated>:1
		__orchestrion_iastprop.Concat3(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:141
			"x", window, "y")
	converted :=
//line <generated>:1
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:142
		namedString(
//line <generated>:1
			__orchestrion_iastprop.BytesToString(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:142
				data))
	for _, c := range []struct {
		value         string
		start, length uint32
	}{
		{concat, 1, 2}, {string(converted), 0, 4},
	} {
		var got []taint.Range
		taint.VisitString(c.value, func(r taint.Range) bool {
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:147
			got = append(got, r)
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/operators_test.go:147
			return true
		})
		if len(got) != 1 || got[0].Start != c.start || got[0].Length != c.length || got[0].Source.Name != "q" || got[0].Source.Value != "abcd" {
			t.Fatalf("value=%q ranges=%+v", c.value, got)
		}
	}
	if taint.IsTaintedString("xbcy") || taint.IsTaintedString("abcd") {
		t.Fatal("clean literal tainted")
	}
	wide := s + "1" + "2" + "3" + "4" + "5" + "6" + "7" + "8" + "9" + "a" + "b" + "c" + "d" + "e" + "f" + "g"
	inplace := "x"
	inplace += s
	if taint.IsTaintedString(wide) || taint.IsTaintedString(inplace) {
		t.Fatal("unsupported concat should miss")
	}
}
