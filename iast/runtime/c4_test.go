// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package runtime_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestC4ConstantExpressionsAreNotEvaluated checks that the hooks cannot
// change what Go evaluates: Go does not evaluate these operands, and the
// runtime hooks run only when Go calls the runtime function.
func TestC4ConstantExpressionsAreNotEvaluated(t *testing.T) {
	requireWoven(t)
	a := taintString(t, "left")
	b, c := "right", "other"

	before := entries()
	const n = len([2]string{"x", "y"})
	got := len([2]string{a + b, c})
	require.Equal(t, n, got)
	require.Equal(t, before, entries(), "len of an array literal does not evaluate a + b")

	var nilBytes []byte
	require.NotPanics(t, func() {
		sinkInt = cap([4][]byte{nilBytes[1:3]})
	}, "cap of an array literal does not evaluate the slice of a nil slice")
	require.Equal(t, 4, sinkInt)

	count := 0
	before = entries()
	for i := range [2]string{a + b} {
		count += i + 1
	}
	require.Equal(t, 3, count)
	require.Equal(t, before, entries(), "range with only the index does not evaluate a + b")
}

// TestC4EvaluationOrder checks that operands are evaluated once and in order.
func TestC4EvaluationOrder(t *testing.T) {
	requireWoven(t)
	tainted := taintString(t, "b")
	order := make([]int, 0, 3)
	operand := func(index int, value string) string { order = append(order, index); return value }
	require.Equal(t, "abc", operand(1, "a")+operand(2, tainted)+operand(3, "c"))
	require.Equal(t, []int{1, 2, 3}, order)
	calls := 0
	conversion := func() []byte { calls++; return taintBytes(t, "abc") }
	require.Equal(t, "abc", string(conversion()))
	require.Equal(t, 1, calls)
	defer func() { require.NotNil(t, recover(), "a slice out of range still panics") }()
	value := tainted
	sinkString = value[0 : len(value)+1]
}

// TestNoSourceExpressionAspects checks the hard rule of the plan (decision
// D5): no aspect of the module instruments an operator or another source
// expression (concatenation, conversion, slicing). Every wrap-expression
// aspect wraps a call expression: a call is already not constant, so a wrapper
// call does not change the evaluation.
func TestNoSourceExpressionAspects(t *testing.T) {
	root := filepath.Join("..", "..")
	var files []string
	require.NoError(t, filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "testdata") && path != root {
			return filepath.SkipDir
		}
		if entry.Name() == "orchestrion.yml" {
			files = append(files, path)
		}
		return nil
	}))
	require.NotEmpty(t, files)
	call := regexp.MustCompile(`(?m)^\s*-?\s*(function-call|method-call):`)
	forbidden := regexp.MustCompile(`string-concat|type-conversion|slice-expression|binary-expression|composite-literal`)
	for _, file := range files {
		contents, err := os.ReadFile(file)
		require.NoError(t, err)
		require.False(t, forbidden.Match(contents), "%s uses a source-expression join point", file)
		for _, aspect := range strings.Split(string(contents), "\n  - id: ")[1:] {
			if !strings.Contains(aspect, "wrap-expression:") {
				continue
			}
			id, _, _ := strings.Cut(aspect, "\n")
			require.Regexp(t, call, aspect, "%s: aspect %q wraps an expression that is not a call", file, id)
		}
	}
}
