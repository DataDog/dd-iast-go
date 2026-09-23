package reviewf4

import (
	"os"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/reviewf4native"
	"github.com/DataDog/dd-iast-go/internal/taint/operatorbridge"
	"github.com/DataDog/orchestrion/runtime/built"
)

var (
	intSink  int
	boolSink bool
)

func TestDisabledOperatorAllocationParity(t *testing.T) {
	if os.Getenv("REVIEW_WOVEN") == "1" && !built.WithOrchestrion {
		t.Fatal("expected woven build")
	}
	if operatorbridge.HasValues() {
		t.Fatal("expected inactive operator bridge")
	}

	a, b := "abc", "def"
	value := []byte("abcdef")
	cases := []struct {
		name     string
		native   func()
		injected func()
	}{
		{
			name: "concat-in-len",
			native: func() {
				reviewf4native.ConcatLen(a, b)
			},
			injected: func() {
				intSink = len(a + b)
			},
		},
		{
			name: "concat-in-comparison",
			native: func() {
				reviewf4native.ConcatCompare(a, b)
			},
			injected: func() {
				boolSink = a+b == "abcdef"
			},
		},
		{
			name: "conversion-used-by-len",
			native: func() {
				reviewf4native.ConversionLen(value)
			},
			injected: func() {
				converted := string(value)
				intSink = len(converted)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			native := testing.AllocsPerRun(200, tc.native)
			injected := testing.AllocsPerRun(200, tc.injected)
			t.Logf("native=%.0f injected=%.0f allocations/op", native, injected)
			if injected != native {
				t.Fatalf("disabled instrumentation changes allocation count")
			}
		})
	}
}
