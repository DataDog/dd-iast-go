// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package text_test

import (
	"bytes"
	"context"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/stretchr/testify/require"
)

// beginOther starts a second active request analysis (begin must run first:
// it sets the configuration).
func beginOther(t *testing.T) request.Analysis {
	t.Helper()
	require.True(t, config.Enabled)
	_, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)
	a, ok := scope.Analysis()
	require.True(t, ok)
	return a
}

// TestTwoOwners is the case of plan section 9.1 item 3: ToUpper(a+b) with 2
// sources of 2 requests. Each request sees only its own source; the bytes of
// the other request are foreign.
func TestTwoOwners(t *testing.T) {
	a := begin(t)
	b := beginOther(t)
	first := source(t, a, "first", "ab")
	second := source(t, b, "second", "cd")
	input := first + "-" + second

	t.Run("positional", func(t *testing.T) {
		got := strings.ToUpper(input)
		require.Equal(t, "AB-CD", got)
		require.Equal(t, []span{{0, 2}, {3, 5}}, stringSpans(got))
		require.Equal(t, []string{"0-2=first", "3-5=foreign"}, attributed(t, a, got))
		require.Equal(t, []string{"0-2=foreign", "3-5=second"}, attributed(t, b, got))
	})

	t.Run("coarse", func(t *testing.T) {
		got := strings.ToUpper("é" + input)
		require.Equal(t, "ÉAB-CD", got)
		require.Equal(t, []span{{0, 7}}, stringSpans(got))
		// Coarse: one segment over the whole output for each request, with
		// the first source of that request (plan section 4.3).
		require.Equal(t, []string{"0-7=first"}, attributed(t, a, got))
		require.Equal(t, []string{"0-7=second"}, attributed(t, b, got))
	})
}

// TestHooksUnderGCAndStackGrowth checks the uintptr contract of plan section
// 6.1 rule 5: the hooks keep their memory alive while they give addresses to
// the runtime and to propbridge. The test runs the hooks on deep stacks (the
// stack moves) while other goroutines force garbage collections.
func TestHooksUnderGCAndStackGrowth(t *testing.T) {
	a := begin(t)
	value := source(t, a, "q", "héllo wörld")
	rounds := 300
	if testing.Short() {
		rounds = 30
	}
	stop := make(chan struct{})
	var gc sync.WaitGroup
	gc.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				runtime.GC()
			}
		}
	})
	defer func() {
		close(stop)
		gc.Wait()
	}()

	var deep func(depth int) []string
	deep = func(depth int) []string {
		var pad [256]byte // grows the stack at each level
		if depth > 0 {
			out := deep(depth - 1)
			return append(out, string(pad[:1]))
		}
		input := "x=" + value
		var buf bytes.Buffer
		buf.WriteString(input)
		return []string{
			strings.ToUpper(input),
			strings.Map(func(r rune) rune { return r + 1 }, input),
			url.QueryEscape(input),
			strconv.Quote(input),
			buf.String(),
		}
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for i := range rounds {
				out := deep(i % 64)
				for _, s := range out[:5] {
					if len(stringSpans(s)) == 0 {
						t.Errorf("round %d: %q lost its taint", i, s)
						return
					}
				}
			}
		})
	}
	wg.Wait()
	require.Equal(t, []string{"0-15=q"}, attributed(t, a, strings.ToUpper("x="+value)))
}

// TestConcurrentHooks runs the hooks of all packages on many goroutines with
// shared tainted inputs (run it with -race).
func TestConcurrentHooks(t *testing.T) {
	a := begin(t)
	value := source(t, a, "q", "a'b c&d/é")
	data := sourceBytes(t, a, "b", "bytes-ÉTÉ")
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				var sb strings.Builder
				sb.WriteString(value)
				_, _ = sb.Write(data)
				var buf bytes.Buffer
				buf.WriteString(value)
				buf.Write(data)
				buf.WriteByte('!')
				buf.WriteRune('界')
				outs := []string{
					sb.String(), buf.String(),
					strings.ToLower(value), strings.ToTitle(value), strings.Repeat(value, 3),
					strings.NewReplacer("'", "''").Replace(value), strings.ToValidUTF8(value, "?"),
					string(bytes.ToUpper(data)), string(bytes.Join([][]byte{data, data}, []byte(","))),
					string(bytes.ReplaceAll(data, []byte("-"), []byte("+"))), string(bytes.Repeat(data, 2)),
					url.QueryEscape(value), url.PathEscape(value), strconv.Quote(value),
				}
				for _, s := range outs {
					if len(stringSpans(s)) == 0 {
						t.Errorf("%q lost its taint", s)
						return
					}
				}
			}
		})
	}
	wg.Wait()
}
