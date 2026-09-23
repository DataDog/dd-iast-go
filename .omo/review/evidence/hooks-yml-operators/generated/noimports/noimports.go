//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/noimports/noimports.go:1:1
package noimports

//line <generated>:1
import __orchestrion_iastprop "github.com/DataDog/dd-iast-go/iast/propagation"

//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/noimports/noimports.go:3
func Concat(a, b string) string {
	return __orchestrion_iastprop. //line <generated>:1
					Concat2(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/noimports/noimports.go:3
			a, b)
}
func Slice(s string) string {
	return __orchestrion_iastprop. //line <generated>:1
					StringSliceLow(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/noimports/noimports.go:4
			s, 1)
}
func Convert(b []byte) string {
	return string( //line <generated>:1
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/noimports/noimports.go:5

//line <generated>:1
		__orchestrion_iastprop.BytesToString(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/noimports/noimports.go:5
			b))
}
