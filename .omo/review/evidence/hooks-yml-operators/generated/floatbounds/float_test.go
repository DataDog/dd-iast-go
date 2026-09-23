//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/floatbounds/float_test.go:1:1
package floatbounds

import (
	"testing"

//line <generated>:1
	__orchestrion_iastprop "github.com/DataDog/dd-iast-go/iast/propagation"
)

//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/floatbounds/float_test.go:5
func TestIntegralUntypedBounds(t *testing.T) {
	s := "abcd"
	if
//line <generated>:1
	__orchestrion_iastprop.StringSliceBounds(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/floatbounds/float_test.go:7
		s, 1.0, 3.0) != "bc" ||
//line <generated>:1
		__orchestrion_iastprop.StringSliceBounds(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/floatbounds/float_test.go:7
			s, complex(1, 0), 3) != "bc" {
		t.Fatal("integral untyped bounds")
	}
	b := []byte("abcd")
	if string(
//line <generated>:1
		__orchestrion_iastprop.BytesSliceFull(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/floatbounds/float_test.go:11
			b, 1.0, 3.0, 4.0)) != "bc" {
		t.Fatal("integral untyped byte bounds")
	}
}
