// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package stream_test

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// io.ReadAll copies each chunk into the final slice: the bits follow (plan
// section 6.2). Port of the sizes of PR #39 TestReadAllBodySizeBound: here
// the bits stay on all the bytes; the body bytes after 64 KiB are foreign at
// the sink (plan section 9.2).
func TestReadAllBody(t *testing.T) {
	for _, size := range []int{2, 12, 511, 512, 600, 5000, 64 << 10, 70000} {
		for _, chunk := range []int{0, 100} {
			t.Run(fmt.Sprintf("%d/chunk=%d", size, chunk), func(t *testing.T) {
				_, a := begin(t)
				want := noise(size)
				data, err := io.ReadAll(newBody(t, a, want, chunk))
				require.NoError(t, err)
				require.Equal(t, want, string(data))
				require.Equal(t, [][2]int{{0, size}}, rangesBytes(data))
				part := data[:min(size, 1000)]
				require.Equal(t, []string{fmt.Sprintf("0-%d=%s", len(part), bodyLabel)}, attributedBytes(t, a, part))
				if size > 64<<10 {
					// Short content matches (some bytes) are valid: check
					// only that most of the tail is foreign.
					tail := attributedBytes(t, a, data[size-100:])
					require.NotEqual(t, []string{"0-100=" + bodyLabel}, tail)
					require.Contains(t, strings.Join(tail, ","), "=foreign")
				}
			})
		}
	}
}

// noise returns n letters with no repeated pattern (a content match of a
// part finds only its own place).
func noise(n int) string {
	b := make([]byte, n)
	x := uint32(2463534242)
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = 'a' + byte(x%26)
	}
	return string(b)
}

// Port of PR #39 TestReadAllEOFWithData: the last read returns the data and
// io.EOF.
func TestReadAllEOFWithData(t *testing.T) {
	_, a := begin(t)
	b := newBody(t, a, "request-body", 0)
	b.eof = true
	data, err := io.ReadAll(b)
	require.NoError(t, err)
	require.Equal(t, "request-body", string(data))
	require.Equal(t, 1, b.reads)
	require.Equal(t, []string{"0-12=" + bodyLabel}, attributedBytes(t, a, data))
}

var errRead = errors.New("read failed")

// failAfter returns the data of r, then err.
type failAfter struct {
	r   io.Reader
	err error
}

func (f *failAfter) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if err == io.EOF {
		err = f.err
	}
	return n, err
}

// Port of PR #39 TestReadAllThroughSupportedWrappers. Here the bits follow
// the bytes through all the wrappers, also when a clean input is in front
// (PR #39: not exclusive, no taint).
func TestReadAllThroughWrappers(t *testing.T) {
	for name, multi := range map[string]func(io.Reader) io.Reader{
		"alone":       func(r io.Reader) io.Reader { return io.MultiReader(r) },
		"clean input": func(r io.Reader) io.Reader { return io.MultiReader(strings.NewReader(heapString("clean-")), r) },
	} {
		t.Run(name, func(t *testing.T) {
			_, a := begin(t)
			input := &failAfter{r: newBody(t, a, "request-body", 0), err: errRead}
			var side bytes.Buffer
			tee := io.TeeReader(io.LimitReader(input, 1024), &side)
			data, err := io.ReadAll(bufio.NewReaderSize(multi(tee), 32))
			require.ErrorIs(t, err, errRead)
			require.True(t, strings.HasSuffix(string(data), "request-body"))
			require.Equal(t, "request-body", side.String())
			// The side writer is a hooked bytes.Buffer: its copy keeps the
			// bits and the source of the body (plan section 9.2).
			require.Equal(t, [][2]int{{0, len("request-body")}}, rangesBytes(side.Bytes()))
			require.Equal(t, []string{fmt.Sprintf("0-%d=%s", len("request-body"), bodyLabel)}, attributedBytes(t, a, side.Bytes()))
			start := len(data) - len("request-body")
			require.Equal(t, [][2]int{{start, len(data)}}, rangesBytes(data))
			require.Equal(t, []string{fmt.Sprintf("%d-%d=%s", start, len(data), bodyLabel)}, attributedBytes(t, a, data))
		})
	}
}

// Port of PR #39 TestReadAllStringReaderIsUnchanged: a clean reader gives
// clean bytes.
func TestReadAllCleanReader(t *testing.T) {
	_, a := begin(t)
	_ = param(t, a, "q", "robert")
	for _, size := range []int{5, 600, 5000} {
		data, err := io.ReadAll(strings.NewReader(heapString(strings.Repeat("x", size))))
		require.NoError(t, err)
		require.Len(t, data, size)
		require.Empty(t, rangesBytes(data))
	}
}

// A clean reader after a tainted one: only the tainted part has bits, also
// across the chunks of ReadAll.
func TestReadAllMixedChunks(t *testing.T) {
	_, a := begin(t)
	clean := heapString(strings.Repeat("c", 3000))
	data, err := io.ReadAll(io.MultiReader(strings.NewReader(clean), newBody(t, a, strings.Repeat("b", 3000), 700), strings.NewReader(clean)))
	require.NoError(t, err)
	require.Len(t, data, 9000)
	require.Equal(t, [][2]int{{3000, 6000}}, rangesBytes(data))
}
