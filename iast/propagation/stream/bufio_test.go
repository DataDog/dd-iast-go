// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package stream_test

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Port of the sizes of PR #39 testPropagation (bufio): the bits follow the
// bytes for all buffer sizes (PR #39: no propagation above 4096).
func TestBufioReadAllSizes(t *testing.T) {
	for _, size := range []int{16, 4096, 4097} {
		for _, data := range []string{"request-body", noise(10000)} {
			t.Run(fmt.Sprintf("%d/%d", size, len(data)), func(t *testing.T) {
				_, a := begin(t)
				r := bufio.NewReaderSize(newBody(t, a, data, 700), size)
				got, err := io.ReadAll(r)
				require.NoError(t, err)
				require.Equal(t, data, string(got))
				require.Equal(t, [][2]int{{0, len(data)}}, rangesBytes(got))
				part := got[:min(len(got), 500)]
				require.Equal(t, []string{fmt.Sprintf("0-%d=%s", len(part), bodyLabel)}, attributedBytes(t, a, part))
			})
		}
	}
}

// Plan section 9.1 item 4: the first small read with clean buffers, and
// nested readers.
func TestBufioSmallReadsAndNestedReaders(t *testing.T) {
	_, a := begin(t)
	const data = "name=robert&id=42;tail"
	inner := bufio.NewReaderSize(newBody(t, a, data, 5), 16)
	outer := bufio.NewReaderSize(inner, 64)
	require.NotSame(t, inner, outer)

	p := make([]byte, 3)
	n, err := outer.Read(p)
	require.NoError(t, err)
	require.Equal(t, [][2]int{{0, n}}, rangesBytes(p[:n]))

	peek, err := outer.Peek(4)
	require.NoError(t, err)
	require.Equal(t, [][2]int{{0, 4}}, rangesBytes(peek))

	line, err := outer.ReadSlice('&')
	require.NoError(t, err)
	require.Equal(t, [][2]int{{0, len(line)}}, rangesBytes(line))

	field, err := outer.ReadBytes(';')
	require.NoError(t, err)
	require.Equal(t, "id=42;", string(field))
	require.Equal(t, [][2]int{{0, 6}}, rangesBytes(field))
	require.Equal(t, []string{"0-6=" + bodyLabel}, attributedBytes(t, a, field))

	rest, err := io.ReadAll(outer)
	require.NoError(t, err)
	require.Equal(t, "tail", string(rest))
	require.Equal(t, [][2]int{{0, 4}}, rangesBytes(rest))
}

// ReadBytes and ReadString across several buffers (the full buffers are
// copied with bytes.Clone and strings.Builder: the hooks of
// iast/propagation/text).
func TestBufioReadBytesAcrossBuffers(t *testing.T) {
	_, a := begin(t)
	data := noise(100) + "\n" + noise(50) + "\n"
	r := bufio.NewReaderSize(newBody(t, a, data, 7), 16)
	line, err := r.ReadBytes('\n')
	require.NoError(t, err)
	require.Len(t, line, 101)
	require.Equal(t, [][2]int{{0, 101}}, rangesBytes(line))
	require.Equal(t, []string{"0-101=" + bodyLabel}, attributedBytes(t, a, line))
	s, err := r.ReadString('\n')
	require.NoError(t, err)
	require.Len(t, s, 51)
	require.Equal(t, [][2]int{{0, 51}}, rangesString(s))
}

// The direct path of Read (len(p) >= the buffer size): the read goes to p.
func TestBufioDirectRead(t *testing.T) {
	_, a := begin(t)
	r := bufio.NewReaderSize(newBody(t, a, "request-body-data", 0), 16)
	p := make([]byte, 64)
	n, err := r.Read(p)
	require.NoError(t, err)
	require.Equal(t, 17, n)
	require.Equal(t, [][2]int{{0, 17}}, rangesBytes(p))
}

// Plan section 9.1 item 5: a tainted read, then Reset with a clean reader:
// the new bytes are clean (no false finding).
func TestBufioResetToCleanReader(t *testing.T) {
	_, a := begin(t)
	r := bufio.NewReaderSize(newBody(t, a, noise(40), 0), 16)
	first := make([]byte, 8)
	_, err := io.ReadFull(r, first)
	require.NoError(t, err)
	require.Equal(t, [][2]int{{0, 8}}, rangesBytes(first))

	clean := heapString("clean-data-that-is-long")
	r.Reset(strings.NewReader(clean))
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, clean, string(got))
	require.Empty(t, rangesBytes(got))

	// The same with a small Read and a Peek.
	r.Reset(newBody(t, a, noise(40), 0))
	_, err = r.Peek(16)
	require.NoError(t, err)
	r.Reset(strings.NewReader(clean))
	p := make([]byte, 4)
	_, err = r.Read(p)
	require.NoError(t, err)
	require.Empty(t, rangesBytes(p))
	peek, err := r.Peek(8)
	require.NoError(t, err)
	require.Empty(t, rangesBytes(peek))
}

// sequence returns the result of each reader once, in order (one Read
// for each), then io.EOF.
type sequence struct {
	reads []func(p []byte) (int, error)
}

func (s *sequence) Read(p []byte) (int, error) {
	if len(s.reads) == 0 {
		return 0, io.EOF
	}
	f := s.reads[0]
	s.reads = s.reads[1:]
	return f(p)
}

func cleanRead(data string) func(p []byte) (int, error) {
	return func(p []byte) (int, error) { return copy(p, data), nil }
}

// Plan section 6.2, read rule: a short read and a zero read into a tainted
// buffer. The written prefix is clean, the tail (and its aliases) keeps its
// bits.
func TestBufioReadRule(t *testing.T) {
	t.Run("short read", func(t *testing.T) {
		_, a := begin(t)
		tainted := newBody(t, a, strings.Repeat("a", 16), 0)
		r := bufio.NewReaderSize(&sequence{reads: []func([]byte) (int, error){tainted.Read, cleanRead("cccc")}}, 16)
		alias, err := r.Peek(16)
		require.NoError(t, err)
		require.Equal(t, [][2]int{{0, 16}}, rangesBytes(alias))
		_, err = r.Discard(16)
		require.NoError(t, err)

		got, err := r.Peek(4)
		require.NoError(t, err)
		require.Equal(t, "cccc", string(got))
		require.Empty(t, rangesBytes(got), "the new bytes must be clean")
		require.Equal(t, "ccccaaaaaaaaaaaa", string(alias))
		require.Equal(t, [][2]int{{4, 16}}, rangesBytes(alias), "the tail keeps its bits")
	})
	t.Run("zero read", func(t *testing.T) {
		_, a := begin(t)
		tainted := newBody(t, a, strings.Repeat("a", 16), 0)
		zero := func([]byte) (int, error) { return 0, nil }
		r := bufio.NewReaderSize(&sequence{reads: []func([]byte) (int, error){tainted.Read, zero, cleanRead("cc")}}, 16)
		alias, err := r.Peek(16)
		require.NoError(t, err)
		_, err = r.Discard(16)
		require.NoError(t, err)
		got, err := r.Peek(2)
		require.NoError(t, err)
		require.Equal(t, "cc", string(got))
		require.Empty(t, rangesBytes(got))
		require.Equal(t, [][2]int{{2, 16}}, rangesBytes(alias))
	})
	t.Run("direct read into tainted p", func(t *testing.T) {
		_, a := begin(t)
		p := []byte(string(paramBytes(t, a, "q", strings.Repeat("t", 32))))
		require.Equal(t, [][2]int{{0, 32}}, rangesBytes(p), "string-to-slice propagation is on")
		r := bufio.NewReaderSize(&sequence{reads: []func([]byte) (int, error){cleanRead("clean")}}, 16)
		n, err := r.Read(p)
		require.NoError(t, err)
		require.Equal(t, 5, n)
		require.Equal(t, [][2]int{{5, 32}}, rangesBytes(p))
	})
}

type panicValue struct{ s string }

// Plan section 6.2, read rule: a panic of the delegated Read goes on
// unchanged.
func TestBufioReadRulePanickingReader(t *testing.T) {
	_, a := begin(t)
	tainted := newBody(t, a, strings.Repeat("a", 16), 0)
	want := &panicValue{"boom"}
	boom := func([]byte) (int, error) { panic(want) }
	r := bufio.NewReaderSize(&sequence{reads: []func([]byte) (int, error){tainted.Read, boom}}, 16)
	_, err := r.Peek(16)
	require.NoError(t, err)
	_, err = r.Discard(16)
	require.NoError(t, err)
	func() {
		defer func() {
			require.Same(t, want, recover())
		}()
		_, _ = r.Peek(1)
		t.Fatal("no panic")
	}()
}

// Port of PR #39 TestKnownLimitBufioValueCopySharesBuffer (residual R15). A
// copy of a bufio.Reader value shares its buffer with the original. The
// program bug stays (the original returns the bytes of the reader of the
// copy), but with the read rule these bytes are clean: no mis-attribution to
// the request of the original (PR #39: attributed to A).
func TestBufioValueCopySharesBuffer(t *testing.T) {
	_, a := begin(t)
	p := bufio.NewReaderSize(newBody(t, a, strings.Repeat("a", 24), 0), 16)
	_, err := p.Peek(16)
	require.NoError(t, err)
	q := *p
	q.Reset(strings.NewReader(heapString("cccccccc")))
	_, err = q.Read(make([]byte, 4))
	require.NoError(t, err)
	data, err := io.ReadAll(p)
	require.NoError(t, err)
	require.Equal(t, "cccccccc"+strings.Repeat("a", 16), string(data))
	require.Equal(t, [][2]int{{8, 24}}, rangesBytes(data))
	require.Equal(t, []string{"8-24=" + bodyLabel}, attributedBytes(t, a, data))
}

// The number of delegated reads does not change (the application reader
// runs as in the original body).
func TestBufioReadCount(t *testing.T) {
	_, a := begin(t)
	b := newBody(t, a, noise(1000), 0)
	got, err := io.ReadAll(bufio.NewReaderSize(b, 2048))
	require.NoError(t, err)
	require.Len(t, got, 1000)
	require.Equal(t, [][2]int{{0, 1000}}, rangesBytes(got))
	// One read fills the buffer with the 1000 bytes; ReadAll gets them in
	// 2 copies (512 + 488); one more read gives io.EOF.
	require.Equal(t, 2, b.reads)
}

// The slide of fill moves the unread bytes to the start of the buffer: their
// bits move with them (the bytes at the start had different bits).
func TestBufioFillSlide(t *testing.T) {
	_, a := begin(t)
	r := bufio.NewReaderSize(newScripted(t, a,
		[]seg{{"cccccc", false}, {"tttt", true}},
		[]seg{{"dddd", false}},
	), 16)
	p := make([]byte, 6)
	_, err := io.ReadFull(r, p)
	require.NoError(t, err)
	require.Empty(t, rangesBytes(p))
	got, err := r.Peek(8)
	require.NoError(t, err)
	require.Equal(t, "ttttdddd", string(got))
	require.Equal(t, [][2]int{{0, 4}}, rangesBytes(got))
	require.Equal(t, []string{"0-4=" + bodyLabel}, attributedBytes(t, a, got))
}
