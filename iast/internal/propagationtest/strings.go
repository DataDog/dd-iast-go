// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package testapp contains root-application calls used by woven tests.
package testapp

import (
	"fmt"
	"iter"
	"net/url"
	"strconv"
	"strings"
)

func Clone(value string) string                          { return strings.Clone(value) }
func Cut(value, separator string) (string, string, bool) { return strings.Cut(value, separator) }
func CutPrefix(value, prefix string) (string, bool)      { return strings.CutPrefix(value, prefix) }
func CutSuffix(value, suffix string) (string, bool)      { return strings.CutSuffix(value, suffix) }
func Split(value, separator string) []string             { return strings.Split(value, separator) }
func SplitN(value, separator string, count int) []string {
	return strings.SplitN(value, separator, count)
}
func SplitAfter(value, separator string) []string { return strings.SplitAfter(value, separator) }
func SplitAfterN(value, separator string, count int) []string {
	return strings.SplitAfterN(value, separator, count)
}
func SplitSeq(value, separator string) iter.Seq[string] {
	return strings.SplitSeq(value, separator)
}
func SplitAfterSeq(value, separator string) iter.Seq[string] {
	return strings.SplitAfterSeq(value, separator)
}
func Lines(value string) iter.Seq[string] { return strings.Lines(value) }
func Fields(value string) []string        { return strings.Fields(value) }
func FieldsFunc(value string, predicate func(rune) bool) []string {
	return strings.FieldsFunc(value, predicate)
}
func FieldsSeq(value string) iter.Seq[string] { return strings.FieldsSeq(value) }
func FieldsFuncSeq(value string, predicate func(rune) bool) iter.Seq[string] {
	return strings.FieldsFuncSeq(value, predicate)
}
func Join(elements []string, separator string) string { return strings.Join(elements, separator) }
func Repeat(value string, count int) string           { return strings.Repeat(value, count) }
func Replace(value, old, replacement string, count int) string {
	return strings.Replace(value, old, replacement, count)
}
func ReplaceAll(value, old, replacement string) string {
	return strings.ReplaceAll(value, old, replacement)
}
func ReplacerReplace(value string) string {
	return strings.NewReplacer("Attack", "Changed").Replace(value)
}
func ReplacerReplacement(value, replacement string) string {
	return strings.NewReplacer("plain", replacement).Replace(value)
}
func Trim(value, cutset string) string       { return strings.Trim(value, cutset) }
func TrimSpace(value string) string          { return strings.TrimSpace(value) }
func TrimLeft(value, cutset string) string   { return strings.TrimLeft(value, cutset) }
func TrimRight(value, cutset string) string  { return strings.TrimRight(value, cutset) }
func TrimPrefix(value, prefix string) string { return strings.TrimPrefix(value, prefix) }
func TrimSuffix(value, suffix string) string { return strings.TrimSuffix(value, suffix) }
func TrimFunc(value string, predicate func(rune) bool) string {
	return strings.TrimFunc(value, predicate)
}
func TrimLeftFunc(value string, predicate func(rune) bool) string {
	return strings.TrimLeftFunc(value, predicate)
}
func TrimRightFunc(value string, predicate func(rune) bool) string {
	return strings.TrimRightFunc(value, predicate)
}

func ToLower(value string) string                      { return strings.ToLower(value) }
func ToUpper(value string) string                      { return strings.ToUpper(value) }
func ToTitle(value string) string                      { return strings.ToTitle(value) }
func Map(mapping func(rune) rune, value string) string { return strings.Map(mapping, value) }
func ToValidUTF8(value, replacement string) string     { return strings.ToValidUTF8(value, replacement) }
func Sprint(arguments ...any) string                   { return fmt.Sprint(arguments...) }
func Sprintf(format string, arguments ...any) string   { return fmt.Sprintf(format, arguments...) }
func Sprintln(arguments ...any) string                 { return fmt.Sprintln(arguments...) }
func QueryEscape(value string) string                  { return url.QueryEscape(value) }
func PathEscape(value string) string                   { return url.PathEscape(value) }
func QueryUnescape(value string) (string, error)       { return url.QueryUnescape(value) }
func PathUnescape(value string) (string, error)        { return url.PathUnescape(value) }
func Quote(value string) string                        { return strconv.Quote(value) }
func QuoteToASCII(value string) string                 { return strconv.QuoteToASCII(value) }
func QuoteToGraphic(value string) string               { return strconv.QuoteToGraphic(value) }
func Unquote(value string) (string, error)             { return strconv.Unquote(value) }

func IndirectClone(value string) string {
	clone := strings.Clone
	return clone(value)
}
