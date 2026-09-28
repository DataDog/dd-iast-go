// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package propagation contains drop-in call-site wrappers for named taint
// propagation operations. It is instrumentation implementation, not a public
// taint API.
package propagation

import (
	"strings"

	internal "github.com/DataDog/dd-iast-go/internal/taint/propagation"
)

// StringsClone wraps strings.Clone.
func StringsClone(value string) string {
	result := strings.Clone(value)
	return internal.AdoptStringCopy(value, result)
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
