// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package text_test

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The reader tests check the hooks of bytes.Reader and strings.Reader: Read
// and ReadAt copy the bits of the bytes that they write (exact copy). The
// destination is reused memory: a clean source clears its old bits, and the
// bytes that the read does not write keep their bits.

// readerUnderTest is a bytes.Reader or a strings.Reader on the same data.
type readerUnderTest interface {
	io.Reader
	io.ReaderAt
	io.WriterTo
	Len() int
}

// readers returns a bytes.Reader and a strings.Reader on data (the memory of
// data, with its bits).
func readers(data []byte) map[string]func() readerUnderTest {
	return map[string]func() readerUnderTest{
		"bytes":   func() readerUnderTest { return bytes.NewReader(data) },
		"strings": func() readerUnderTest { return strings.NewReader(string(data)) },
	}
}

// taintedRun returns heap bytes "pre-" + value + "-post" with a source on
// value only (bytes 4 to 4+len(value)).
func taintedRun(t *testing.T, value []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	buffer.WriteString("pre-")
	buffer.Write(value)
	buffer.WriteString("-post")
	data := buffer.Bytes()
	escapeBytes(data)
	return data
}

func TestReaderReadCopiesBits(t *testing.T) {
	a := begin(t)
	data := taintedRun(t, sourceBytes(t, a, "q", "attack"))
	for name, open := range readers(data) {
		t.Run(name, func(t *testing.T) {
			r := open()
			first := make([]byte, 6)
			escapeBytes(first)
			n, err := r.Read(first)
			require.NoError(t, err)
			require.Equal(t, 6, n)
			require.Equal(t, "pre-at", string(first))
			require.Equal(t, []span{{4, 6}}, bytesSpans(first))
			rest := make([]byte, 64)
			escapeBytes(rest)
			n, err = r.Read(rest)
			require.NoError(t, err)
			require.Equal(t, "tack-post", string(rest[:n]))
			require.Equal(t, []span{{0, 4}}, bytesSpans(rest))
			require.Equal(t, []string{"0-4=q"}, attributedBytes(t, a, rest[:4]))
			// At the end: the original body gives io.EOF.
			n, err = r.Read(rest)
			require.Equal(t, 0, n)
			require.ErrorIs(t, err, io.EOF)
			require.Equal(t, 0, r.Len())
		})
	}
}

func TestReaderReadAtCopiesBits(t *testing.T) {
	a := begin(t)
	data := taintedRun(t, sourceBytes(t, a, "q", "attack"))
	for name, open := range readers(data) {
		t.Run(name, func(t *testing.T) {
			r := open()
			dst := make([]byte, 4)
			escapeBytes(dst)
			n, err := r.ReadAt(dst, 6)
			require.NoError(t, err)
			require.Equal(t, 4, n)
			require.Equal(t, "tack", string(dst))
			require.Equal(t, []span{{0, 4}}, bytesSpans(dst))
			require.Equal(t, []string{"0-4=q"}, attributedBytes(t, a, dst))
			require.Equal(t, len(data), r.Len(), "ReadAt does not move the reader")

			// A short read: io.EOF, and the tail of dst keeps its bits.
			long := make([]byte, 16)
			escapeBytes(long)
			_, err = r.ReadAt(long[:6], 4)
			require.NoError(t, err)
			require.Equal(t, []span{{0, 6}}, bytesSpans(long))
			n, err = r.ReadAt(long[2:], int64(len(data)-3))
			require.ErrorIs(t, err, io.EOF)
			require.Equal(t, 3, n)
			require.Equal(t, "atost", string(long[:5]))
			require.Equal(t, []span{{0, 2}, {5, 6}}, bytesSpans(long), "clean written bytes, the tail keeps its bits")

			// The original errors.
			n, err = r.ReadAt(dst, -1)
			require.Equal(t, 0, n)
			require.ErrorContains(t, err, "negative offset")
			n, err = r.ReadAt(dst, int64(len(data)))
			require.Equal(t, 0, n)
			require.ErrorIs(t, err, io.EOF)
		})
	}
}

func TestReaderCleanReadClearsOldBits(t *testing.T) {
	a := begin(t)
	value := sourceBytes(t, a, "q", "attack-value")
	for name, open := range readers(bytes.Clone([]byte("plain"))) {
		t.Run(name, func(t *testing.T) {
			dst := bytes.Clone(value) // reused memory with old bits
			escapeBytes(dst)
			require.Equal(t, []span{{0, 12}}, bytesSpans(dst))
			n, err := open().Read(dst)
			require.NoError(t, err)
			require.Equal(t, 5, n)
			require.Equal(t, "plaink-value", string(dst))
			require.Equal(t, []span{{5, 12}}, bytesSpans(dst), "only the written bytes lose their bits")

			dst = bytes.Clone(value)
			escapeBytes(dst)
			n, err = open().ReadAt(dst[2:], 0)
			require.ErrorIs(t, err, io.EOF)
			require.Equal(t, 5, n)
			require.Equal(t, []span{{0, 2}, {7, 12}}, bytesSpans(dst))
		})
	}
}

func TestReaderWriteToKeepsBits(t *testing.T) {
	a := begin(t)
	data := taintedRun(t, sourceBytes(t, a, "q", "attack"))
	for name, open := range readers(data) {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			n, err := open().WriteTo(&out)
			require.NoError(t, err)
			require.Equal(t, int64(len(data)), n)
			require.Equal(t, []span{{4, 10}}, bytesSpans(out.Bytes()))
		})
	}
}

// TestReaderJSONDecoder is the pattern json.NewDecoder(bytes.NewReader(b)):
// the decoder reads the document with Read, and the decoded value keeps
// the source.
func TestReaderJSONDecoder(t *testing.T) {
	a := begin(t)
	document := taintedRun(t, sourceBytes(t, a, "body", `{"table":"users; DROP TABLE secret"}`))[4:]
	document = document[:len(document)-5]
	for name, open := range readers(document) {
		t.Run(name, func(t *testing.T) {
			var decoded struct {
				Table string `json:"table"`
			}
			require.NoError(t, json.NewDecoder(open()).Decode(&decoded))
			require.Equal(t, "users; DROP TABLE secret", decoded.Table)
			require.NotEmpty(t, stringSpans(decoded.Table), "the decoded value is tainted")
			require.Equal(t, []string{"0-24=body"}, attributed(t, a, decoded.Table))
		})
	}
}

// TestReaderResultsUnchanged compares the results with the hooks and with
// the hooks inactive (no tainted input: the original body runs).
func TestReaderResultsUnchanged(t *testing.T) {
	a := begin(t)
	tainted := taintedRun(t, sourceBytes(t, a, "q", "attack"))
	clean := bytes.Clone(tainted)
	for _, sizes := range [][]int{{1, 3, 64}, {5, 0, 100}, {64}} {
		for name := range readers(tainted) {
			got := readAllSizes(readers(tainted)[name](), sizes)
			want := readAllSizes(readers(clean)[name](), sizes)
			require.Equal(t, want, got, "%s %v", name, sizes)
		}
	}
}

type readResult struct {
	data string
	n    int
	err  error
}

func readAllSizes(r readerUnderTest, sizes []int) []readResult {
	var out []readResult
	for i := 0; i < 6; i++ {
		b := make([]byte, sizes[i%len(sizes)])
		n, err := r.Read(b)
		out = append(out, readResult{string(b[:n]), n, err})
	}
	for _, off := range []int64{-1, 0, 3, 15, 100} {
		b := make([]byte, 4)
		n, err := r.ReadAt(b, off)
		out = append(out, readResult{string(b[:n]), n, err})
	}
	return out
}
