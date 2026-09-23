package crashdiff

import (
	"context"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

type color string

func (color) String() string { return "constant-red" }

func tainted(t *testing.T, v string) string {
	t.Helper()
	setup()
	ctx, scope, created := request.Begin(context.Background())
	if !created {
		t.Fatal("no scope")
	}
	t.Cleanup(scope.Finish)
	out := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "p"}, v)
	if !taint.IsTaintedString(out) {
		t.Fatal("not tainted")
	}
	return out
}

// TestTargetedEdges probes specific wrapper edge cases and logs observations.
func TestTargetedEdges(t *testing.T) {
	requireWoven(t)
	v := tainted(t, "attacker-input")

	r1 := Woven.Repeat(v, 1)
	t.Logf("Repeat(v,1): alias=%v tainted=%v", unsafe.StringData(r1) == unsafe.StringData(v), taint.IsTaintedString(r1))

	j := Woven.Join([]string{v}, ",")
	jn := Native.Join([]string{v}, ",")
	t.Logf("Join([v], \",\"): woven alias=%v native alias=%v tainted=%v", unsafe.StringData(j) == unsafe.StringData(v), unsafe.StringData(jn) == unsafe.StringData(v), taint.IsTaintedString(j))

	for _, c := range []struct {
		name string
		got  string
	}{
		{"Sprintf(%T)", Woven.Sprintf("type=%T", v)},
		{"Sprintf(%.0s)", Woven.Sprintf("x%.0sy", v)},
		{"Sprintf(%[2]s)", Woven.Sprintf("%[2]s", v, "clean-literal")},
		{"Sprint(Stringer named string)", Woven.Sprint(color(v))},
		{"Sprintf(%d, len)", Woven.Sprintf("%d", len(v))},
	} {
		var ranges []taint.Range
		taint.VisitString(c.got, func(r taint.Range) bool { ranges = append(ranges, r); return true })
		t.Logf("%-30s result=%q tainted=%v ranges=%d", c.name, c.got, len(ranges) > 0, len(ranges))
	}
}
