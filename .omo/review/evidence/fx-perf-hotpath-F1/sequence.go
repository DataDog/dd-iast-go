package seqreview

import (
	"iter"
	"strings"
	"unicode"
)

// These are ordinary application functions returning lazy stdlib iterators.
func Split(value string) iter.Seq[string] {
	return strings.SplitSeq(value, " ")
}

func SplitAfter(value string) iter.Seq[string] {
	return strings.SplitAfterSeq(value, " ")
}

func Lines(value string) iter.Seq[string] {
	return strings.Lines(value)
}

func Fields(value string) iter.Seq[string] {
	return strings.FieldsSeq(value)
}

func FieldsFunc(value string) iter.Seq[string] {
	return strings.FieldsFuncSeq(value, unicode.IsSpace)
}

func ConsumeSplit(value string) int {
	total := 0
	for part := range strings.SplitSeq(value, " ") {
		total += len(part)
	}
	return total
}
