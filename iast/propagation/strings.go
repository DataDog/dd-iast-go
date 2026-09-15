// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package propagation contains drop-in call-site wrappers for named taint
// propagation operations. It is instrumentation implementation, not a public
// taint API.
package propagation

import (
	"iter"
	"strings"

	internal "github.com/DataDog/dd-iast-go/internal/taint/propagation"
)

// StringsClone wraps strings.Clone.
func StringsClone(value string) string {
	result := strings.Clone(value)
	return internal.AdoptStringCopy(value, result)
}

// StringsCut wraps strings.Cut.
func StringsCut(value, separator string) (before, after string, found bool) {
	before, after, found = strings.Cut(value, separator)
	internal.StringWindow(value, before)
	internal.StringWindow(value, after)
	return before, after, found
}

// StringsCutPrefix wraps strings.CutPrefix.
func StringsCutPrefix(value, prefix string) (after string, found bool) {
	after, found = strings.CutPrefix(value, prefix)
	internal.StringWindow(value, after)
	return after, found
}

// StringsCutSuffix wraps strings.CutSuffix.
func StringsCutSuffix(value, suffix string) (before string, found bool) {
	before, found = strings.CutSuffix(value, suffix)
	internal.StringWindow(value, before)
	return before, found
}

// StringsSplit wraps strings.Split.
func StringsSplit(value, separator string) []string {
	result := strings.Split(value, separator)
	internal.StringWindows(value, result)
	return result
}

// StringsSplitN wraps strings.SplitN.
func StringsSplitN(value, separator string, count int) []string {
	result := strings.SplitN(value, separator, count)
	internal.StringWindows(value, result)
	return result
}

// StringsSplitAfter wraps strings.SplitAfter.
func StringsSplitAfter(value, separator string) []string {
	result := strings.SplitAfter(value, separator)
	internal.StringWindows(value, result)
	return result
}

// StringsSplitAfterN wraps strings.SplitAfterN.
func StringsSplitAfterN(value, separator string, count int) []string {
	result := strings.SplitAfterN(value, separator, count)
	internal.StringWindows(value, result)
	return result
}

// StringsSplitSeq wraps strings.SplitSeq.
func StringsSplitSeq(value, separator string) iter.Seq[string] {
	return stringWindowSeq(value, strings.SplitSeq(value, separator))
}

// StringsSplitAfterSeq wraps strings.SplitAfterSeq.
func StringsSplitAfterSeq(value, separator string) iter.Seq[string] {
	return stringWindowSeq(value, strings.SplitAfterSeq(value, separator))
}

// StringsLines wraps strings.Lines.
func StringsLines(value string) iter.Seq[string] {
	return stringWindowSeq(value, strings.Lines(value))
}

// StringsFields wraps strings.Fields.
func StringsFields(value string) []string {
	result := strings.Fields(value)
	internal.StringWindows(value, result)
	return result
}

// StringsFieldsFunc wraps strings.FieldsFunc.
func StringsFieldsFunc(value string, predicate func(rune) bool) []string {
	result := strings.FieldsFunc(value, predicate)
	internal.StringWindows(value, result)
	return result
}

// StringsFieldsSeq wraps strings.FieldsSeq.
func StringsFieldsSeq(value string) iter.Seq[string] {
	return stringWindowSeq(value, strings.FieldsSeq(value))
}

// StringsFieldsFuncSeq wraps strings.FieldsFuncSeq.
func StringsFieldsFuncSeq(value string, predicate func(rune) bool) iter.Seq[string] {
	return stringWindowSeq(value, strings.FieldsFuncSeq(value, predicate))
}

func stringWindowSeq(input string, sequence iter.Seq[string]) iter.Seq[string] {
	return func(yield func(string) bool) {
		inspected := 0
		sequence(func(value string) bool {
			if inspected < 32 {
				internal.StringWindow(input, value)
			}
			inspected++
			return yield(value)
		})
	}
}

// StringsJoin wraps strings.Join.
func StringsJoin(elements []string, separator string) string {
	result := strings.Join(elements, separator)
	return internal.JoinString(elements, separator, result)
}

// StringsRepeat wraps strings.Repeat.
func StringsRepeat(value string, count int) string {
	result := strings.Repeat(value, count)
	return internal.RepeatString(value, result, count)
}

// StringsReplace wraps strings.Replace.
func StringsReplace(value, old, replacement string, count int) string {
	result := strings.Replace(value, old, replacement, count)
	return internal.ReplaceString(value, old, replacement, result, count)
}

// StringsReplaceAll wraps strings.ReplaceAll.
func StringsReplaceAll(value, old, replacement string) string {
	result := strings.ReplaceAll(value, old, replacement)
	return internal.ReplaceString(value, old, replacement, result, -1)
}

// ReplacerReplace wraps strings.Replacer.Replace. Replacement-term provenance
// is not tracked in the first release.
func ReplacerReplace(replacer *strings.Replacer, value string) string {
	result := replacer.Replace(value)
	return internal.CoarseString(result, value)
}

// StringsTrim wraps strings.Trim.
func StringsTrim(value, cutset string) string {
	result := strings.Trim(value, cutset)
	internal.StringWindow(value, result)
	return result
}

// StringsTrimSpace wraps strings.TrimSpace.
func StringsTrimSpace(value string) string {
	result := strings.TrimSpace(value)
	internal.StringWindow(value, result)
	return result
}

// StringsTrimLeft wraps strings.TrimLeft.
func StringsTrimLeft(value, cutset string) string {
	result := strings.TrimLeft(value, cutset)
	internal.StringWindow(value, result)
	return result
}

// StringsTrimRight wraps strings.TrimRight.
func StringsTrimRight(value, cutset string) string {
	result := strings.TrimRight(value, cutset)
	internal.StringWindow(value, result)
	return result
}

// StringsTrimPrefix wraps strings.TrimPrefix.
func StringsTrimPrefix(value, prefix string) string {
	result := strings.TrimPrefix(value, prefix)
	internal.StringWindow(value, result)
	return result
}

// StringsTrimSuffix wraps strings.TrimSuffix.
func StringsTrimSuffix(value, suffix string) string {
	result := strings.TrimSuffix(value, suffix)
	internal.StringWindow(value, result)
	return result
}

// StringsTrimFunc wraps strings.TrimFunc.
func StringsTrimFunc(value string, predicate func(rune) bool) string {
	result := strings.TrimFunc(value, predicate)
	internal.StringWindow(value, result)
	return result
}

// StringsTrimLeftFunc wraps strings.TrimLeftFunc.
func StringsTrimLeftFunc(value string, predicate func(rune) bool) string {
	result := strings.TrimLeftFunc(value, predicate)
	internal.StringWindow(value, result)
	return result
}

// StringsTrimRightFunc wraps strings.TrimRightFunc.
func StringsTrimRightFunc(value string, predicate func(rune) bool) string {
	result := strings.TrimRightFunc(value, predicate)
	internal.StringWindow(value, result)
	return result
}
