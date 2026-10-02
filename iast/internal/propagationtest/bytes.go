// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp

import "bytes"

func BytesClone(v []byte) []byte                            { return bytes.Clone(v) }
func BytesJoin(v [][]byte, sep []byte) []byte               { return bytes.Join(v, sep) }
func BytesRepeat(v []byte, n int) []byte                    { return bytes.Repeat(v, n) }
func BytesCut(v, sep []byte) ([]byte, []byte, bool)         { return bytes.Cut(v, sep) }
func BytesCutPrefix(v, prefix []byte) ([]byte, bool)        { return bytes.CutPrefix(v, prefix) }
func BytesCutSuffix(v, suffix []byte) ([]byte, bool)        { return bytes.CutSuffix(v, suffix) }
func BytesSplit(v, sep []byte) [][]byte                     { return bytes.Split(v, sep) }
func BytesSplitN(v, sep []byte, n int) [][]byte             { return bytes.SplitN(v, sep, n) }
func BytesSplitAfter(v, sep []byte) [][]byte                { return bytes.SplitAfter(v, sep) }
func BytesSplitAfterN(v, sep []byte, n int) [][]byte        { return bytes.SplitAfterN(v, sep, n) }
func BytesFields(v []byte) [][]byte                         { return bytes.Fields(v) }
func BytesFieldsFunc(v []byte, f func(rune) bool) [][]byte  { return bytes.FieldsFunc(v, f) }
func BytesTrim(v []byte, cutset string) []byte              { return bytes.Trim(v, cutset) }
func BytesTrimSpace(v []byte) []byte                        { return bytes.TrimSpace(v) }
func BytesTrimLeft(v []byte, cutset string) []byte          { return bytes.TrimLeft(v, cutset) }
func BytesTrimRight(v []byte, cutset string) []byte         { return bytes.TrimRight(v, cutset) }
func BytesTrimPrefix(v, prefix []byte) []byte               { return bytes.TrimPrefix(v, prefix) }
func BytesTrimSuffix(v, suffix []byte) []byte               { return bytes.TrimSuffix(v, suffix) }
func BytesTrimFunc(v []byte, f func(rune) bool) []byte      { return bytes.TrimFunc(v, f) }
func BytesTrimLeftFunc(v []byte, f func(rune) bool) []byte  { return bytes.TrimLeftFunc(v, f) }
func BytesTrimRightFunc(v []byte, f func(rune) bool) []byte { return bytes.TrimRightFunc(v, f) }
func BytesReplace(v, old, replacement []byte, n int) []byte {
	return bytes.Replace(v, old, replacement, n)
}
func BytesReplaceAll(v, old, replacement []byte) []byte { return bytes.ReplaceAll(v, old, replacement) }
func BytesToLower(v []byte) []byte                      { return bytes.ToLower(v) }
func BytesToUpper(v []byte) []byte                      { return bytes.ToUpper(v) }
func BytesToTitle(v []byte) []byte                      { return bytes.ToTitle(v) }
func BytesMap(f func(rune) rune, v []byte) []byte       { return bytes.Map(f, v) }
func BytesToValidUTF8(v, replacement []byte) []byte     { return bytes.ToValidUTF8(v, replacement) }
