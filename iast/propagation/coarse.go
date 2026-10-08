// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unsafe"

	internal "github.com/DataDog/dd-iast-go/internal/taint/propagation"
)

// StringsToLower wraps strings.ToLower.
func StringsToLower(value string) string {
	return internal.CaseString(value, strings.ToLower(value))
}

// StringsToUpper wraps strings.ToUpper.
func StringsToUpper(value string) string {
	return internal.CaseString(value, strings.ToUpper(value))
}

// StringsToTitle wraps strings.ToTitle.
func StringsToTitle(value string) string {
	return internal.CaseString(value, strings.ToTitle(value))
}

// StringsMap wraps strings.Map.
func StringsMap(mapping func(rune) rune, value string) string {
	return internal.CoarseString(strings.Map(mapping, value), value)
}

// StringsToValidUTF8 wraps strings.ToValidUTF8.
func StringsToValidUTF8(value, replacement string) string {
	result := strings.ToValidUTF8(value, replacement)
	// The native function returns the original string when no repair is needed.
	if len(result) == len(value) && unsafe.StringData(result) == unsafe.StringData(value) {
		return internal.CoarseString(result, value)
	}
	return internal.CoarseString(result, value, replacement)
}

// FmtSprint wraps fmt.Sprint.
func FmtSprint(arguments ...any) string {
	return internal.CoarseFormatString(fmt.Sprint(arguments...), arguments)
}

// FmtSprintf wraps fmt.Sprintf.
func FmtSprintf(format string, arguments ...any) string {
	return internal.CoarseFormattedString(fmt.Sprintf(format, arguments...), format, arguments)
}

// FmtSprintln wraps fmt.Sprintln.
func FmtSprintln(arguments ...any) string {
	return internal.CoarseFormatString(fmt.Sprintln(arguments...), arguments)
}

// URLQueryEscape wraps url.QueryEscape.
func URLQueryEscape(value string) string {
	return internal.CoarseString(url.QueryEscape(value), value)
}

// URLPathEscape wraps url.PathEscape.
func URLPathEscape(value string) string {
	return internal.CoarseString(url.PathEscape(value), value)
}

// URLQueryUnescape wraps url.QueryUnescape.
func URLQueryUnescape(value string) (string, error) {
	result, err := url.QueryUnescape(value)
	return internal.CoarseString(result, value), err
}

// URLPathUnescape wraps url.PathUnescape.
func URLPathUnescape(value string) (string, error) {
	result, err := url.PathUnescape(value)
	return internal.CoarseString(result, value), err
}

// StrconvQuote wraps strconv.Quote.
func StrconvQuote(value string) string {
	return internal.CoarseString(strconv.Quote(value), value)
}

// StrconvQuoteToASCII wraps strconv.QuoteToASCII.
func StrconvQuoteToASCII(value string) string {
	return internal.CoarseString(strconv.QuoteToASCII(value), value)
}

// StrconvQuoteToGraphic wraps strconv.QuoteToGraphic.
func StrconvQuoteToGraphic(value string) string {
	return internal.CoarseString(strconv.QuoteToGraphic(value), value)
}

// StrconvUnquote wraps strconv.Unquote.
func StrconvUnquote(value string) (string, error) {
	result, err := strconv.Unquote(value)
	return internal.CoarseString(result, value), err
}
