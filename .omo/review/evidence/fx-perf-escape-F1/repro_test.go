package reviewf1

import (
	"os"
	"testing"

	"github.com/DataDog/orchestrion/runtime/built"
)

var result int

func TestShortByteConversionAllocation(t *testing.T) {
	raw := []byte("X-Trace-ID")
	cases := []struct {
		name string
		fn   func([]byte) int
	}{
		{name: "local", fn: CountSeparators},
		{name: "returned", fn: CountReturned},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.fn(raw); got != 2 {
				t.Fatalf("wrong separator count: got %d, want 2", got)
			}
			allocs := testing.AllocsPerRun(1000, func() {
				result = tc.fn(raw)
			})
			want := float64(0)
			if built.WithOrchestrion {
				want = 1
			}
			t.Logf("form=%s woven=%t enabled=%q sampling=%q allocs/run=%g",
				tc.name, built.WithOrchestrion, os.Getenv("DD_IAST_ENABLED"),
				os.Getenv("DD_IAST_REQUEST_SAMPLING"), allocs)
			if allocs != want {
				t.Fatalf("allocs/run=%g, want %g", allocs, want)
			}
		})
	}
}

func TestEmptyByteConversionAllocation(t *testing.T) {
	raw := []byte{}
	allocs := testing.AllocsPerRun(1000, func() {
		result = CountSeparators(raw)
	})
	t.Logf("form=empty woven=%t allocs/run=%g", built.WithOrchestrion, allocs)
	if allocs != 0 {
		t.Fatalf("allocs/run=%g, want 0", allocs)
	}
}

func BenchmarkShortHeaderConversion(b *testing.B) {
	raw := []byte("X-Trace-ID")
	b.ReportAllocs()
	for b.Loop() {
		result = CountSeparators(raw)
	}
}
