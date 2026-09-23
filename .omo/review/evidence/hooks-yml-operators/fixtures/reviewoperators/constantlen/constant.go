package constantlen

import "strings"

var _ = strings.Compare

var text = "abcd"
var data = []byte("abcd")

// None of these native expressions contains a function call or receive.
const ConcatLen = len([1]string{text + "x"})
const SliceLen = len([1]string{text[1:3]})
const ConversionLen = len([1]string{string(data)})

var Array [len([1]string{text + "x"})]byte

func Check() int {
	switch 1 {
	case len([1]string{text[1:3]}):
		return 1
	}
	return 0
}
