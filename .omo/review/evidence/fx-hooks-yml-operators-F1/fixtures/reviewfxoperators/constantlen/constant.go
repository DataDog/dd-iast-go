package constantlen

import _ "strings"

var text string = "abcd"

const sliceLength = len([1]string{text[1:3]})

var _ [sliceLength]byte
