//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/constantlen/constant.go:1:1
package constantlen

import (
	"strings"

//line <generated>:1
	__orchestrion_iastprop "github.com/DataDog/dd-iast-go/iast/propagation"
)

//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/constantlen/constant.go:5
var _ = strings.Compare

var text = "abcd"
var data = []byte("abcd")

// None of these native expressions contains a function call or receive.
const ConcatLen = len([1]string{
//line <generated>:1
	__orchestrion_iastprop.Concat2(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/constantlen/constant.go:11
		text, "x")})
const SliceLen = len([1]string{
//line <generated>:1
	__orchestrion_iastprop.StringSliceBounds(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/constantlen/constant.go:12
		text, 1, 3)})
const ConversionLen = len([1]string{string(data)})

var Array [len([1]string{
//line <generated>:1
	__orchestrion_iastprop.Concat2(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/constantlen/constant.go:15
		text, "x")})]byte

func Check() int {
	switch 1 {
	case len([1]string{
//line <generated>:1
		__orchestrion_iastprop.StringSliceBounds(
//line /tmp/ddiast-review/wt/hooks-yml-operators/reviewoperators/constantlen/constant.go:19
			text, 1, 3)}):
		return 1
	}
	return 0
}
