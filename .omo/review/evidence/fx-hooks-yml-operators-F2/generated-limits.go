//line /private/tmp/ddiast-review/wt/fx-hooks-yml-operators-F2/reviewf2/limits.go:1:1
package reviewf2

//line <generated>:1
import __orchestrion_iastprop "github.com/DataDog/dd-iast-go/iast/propagation"

// Realistic customer shapes: untyped float constants used as slice bounds.
//
//line /private/tmp/ddiast-review/wt/fx-hooks-yml-operators-F2/reviewf2/limits.go:4
const maxLen = 1e3 // untyped float constant, integral value

// Truncate caps a string at maxLen bytes.
func Truncate(s string) string {
	if len(s) > maxLen {
		return __orchestrion_iastprop. //line <generated>:1
						StringSliceHigh(
//line /private/tmp/ddiast-review/wt/fx-hooks-yml-operators-F2/reviewf2/limits.go:9
				s, maxLen)
	}
	return s
}

// Header returns the first 2 bytes using an untyped float literal.
func Header(b []byte) []byte {
	return __orchestrion_iastprop. //line <generated>:1
					BytesSliceBounds(
//line /private/tmp/ddiast-review/wt/fx-hooks-yml-operators-F2/reviewf2/limits.go:15
			b, 0, 2.0)
}

// Mid uses a complex-valued integral constant.
func Mid(s string) string {
	return __orchestrion_iastprop. //line <generated>:1
					StringSliceBounds(
//line /private/tmp/ddiast-review/wt/fx-hooks-yml-operators-F2/reviewf2/limits.go:18
			s, complex(1, 0), 3)
}
