// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package text_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/heapbits"
	"github.com/stretchr/testify/require"
)

// The buffer tests port P/iast/propagation/writer_test.go. The bits follow
// the bytes: a write clears the old bits of the bytes that it overwrites,
// and memory that the buffer does not overwrite keeps its bits (also when
// another value aliases it).

func TestBuilderAndBufferPropagation(t *testing.T) {
	a := begin(t)
	input := source(t, a, "q", "attack")
	var buffer bytes.Buffer
	buffer.WriteString("prefix:")
	buffer.WriteString(input)
	buffer.WriteByte('!')
	got := buffer.String()
	require.Equal(t, "prefix:attack!", got)
	require.Equal(t, []span{{7, 13}}, stringSpans(got))
	require.Equal(t, []string{"7-13=q"}, attributed(t, a, got))

	data := sourceBytes(t, a, "b", "bytes")
	var b2 bytes.Buffer
	b2.Write(data)
	require.Equal(t, []span{{0, 5}}, bytesSpans(b2.Bytes()))
	require.Equal(t, []string{"0-5=b"}, attributedBytes(t, a, b2.Bytes()))
}

func TestBufferCopyAppend(t *testing.T) {
	a := begin(t)
	for _, mode := range []string{"string", "bytes", "byte", "rune", "wide-rune", "grow"} {
		t.Run(mode, func(t *testing.T) {
			input := source(t, a, "q", "attack")
			var buffer bytes.Buffer
			buffer.WriteString(input)
			switch mode {
			case "string":
				buffer.WriteString("!")
			case "bytes":
				buffer.Write([]byte("!"))
			case "byte":
				buffer.WriteByte('!')
			case "rune":
				buffer.WriteRune('!')
			case "wide-rune":
				buffer.WriteRune('界')
			case "grow":
				buffer.Grow(4096)
				buffer.WriteString("!")
			}
			require.Equal(t, []span{{0, 6}}, bytesSpans(buffer.Bytes()))
			require.Equal(t, []string{"0-6=q"}, attributedBytes(t, a, buffer.Bytes()))
		})
	}
}

// overwriteModes write clean bytes into reused buffer memory.
var overwriteModes = map[string]func(b *bytes.Buffer){
	"string":    func(b *bytes.Buffer) { b.WriteString("plain!") },
	"bytes":     func(b *bytes.Buffer) { b.Write([]byte("plain!")) },
	"byte":      func(b *bytes.Buffer) { b.WriteString("plain"); b.WriteByte('!') },
	"rune":      func(b *bytes.Buffer) { b.WriteString("plai"); b.WriteRune('界') },
	"read from": func(b *bytes.Buffer) { b.ReadFrom(strings.NewReader("plain!")) },
}

func TestBufferCopyResetThenOverwrite(t *testing.T) {
	a := begin(t)
	for name, write := range overwriteModes {
		t.Run(name, func(t *testing.T) {
			input := source(t, a, "q", "attack")
			var buffer bytes.Buffer
			buffer.Grow(1024) // ReadFrom needs 512 free bytes to reuse the memory
			buffer.WriteString(input)
			view := buffer.Bytes() // aliases the buffer memory
			copied := buffer       // a value copy shares the array
			before := cap(buffer.Bytes())
			buffer.Reset()
			write(&buffer)
			require.Equal(t, before, cap(buffer.Bytes()), "the buffer reused its memory")
			got := buffer.Bytes()
			require.Empty(t, bytesSpans(got[:min(6, len(got))]), "the written bytes have no old bits")
			require.Equal(t, got[:6], view, "the view sees the new bytes")
			require.Empty(t, bytesSpans(view), "the bits follow the bytes")
			require.Empty(t, bytesSpans(copied.Bytes()))
		})
	}
}

func TestBufferPartialOverwriteKeepsTheTail(t *testing.T) {
	a := begin(t)
	input := source(t, a, "q", "attack-value")
	var buffer bytes.Buffer
	buffer.Grow(64)
	buffer.WriteString(input)
	view := buffer.Bytes()
	buffer.Truncate(3)
	require.Equal(t, []span{{0, 3}}, bytesSpans(buffer.Bytes()), "Truncate keeps the bits")
	buffer.WriteString("XY")
	require.Equal(t, "attXYk-value", string(view))
	require.Equal(t, []span{{0, 3}, {5, 12}}, bytesSpans(view), "only the overwritten bytes lose their bits")
	require.Equal(t, []span{{0, 3}}, bytesSpans(buffer.Bytes()))
}

func TestBufferCopyInteriorCompaction(t *testing.T) {
	a := begin(t)
	input := source(t, a, "q", "attack")
	var buffer bytes.Buffer
	buffer.Grow(64)
	c := cap(buffer.Bytes())
	require.Equal(t, 64, c)
	buffer.Write(make([]byte, 40))
	buffer.WriteString(input)
	buffer.Next(36) // 4 zero bytes and "attack" stay (off 36, length 10)
	require.Equal(t, []span{{4, 10}}, bytesSpans(buffer.Bytes()))
	// 20 bytes do not fit after the data (18 free), and 20 <= c/2-10: grow
	// slides the data to the start of the same array.
	buffer.Write(make([]byte, 20))
	require.Equal(t, c, cap(buffer.Bytes()), "grow slid the data, no new array")
	got := buffer.Bytes()
	require.Equal(t, "\x00\x00\x00\x00attack", string(got[:10]))
	require.Equal(t, []span{{4, 10}}, bytesSpans(got))
	require.Equal(t, []string{"4-10=q"}, attributedBytes(t, a, got[:10]))
}

func TestBufferCopyNewArray(t *testing.T) {
	a := begin(t)
	input := source(t, a, "q", "attack")
	var buffer bytes.Buffer
	buffer.WriteString("xx")
	buffer.WriteString(input)
	buffer.Next(1)
	old := buffer.Bytes()
	buffer.Grow(4096) // growSlice: a new array
	got := buffer.Bytes()
	require.NotEqual(t, cap(old), cap(got))
	require.Equal(t, "xattack", string(got))
	require.Equal(t, []span{{1, 7}}, bytesSpans(got))
	require.Equal(t, []span{{1, 7}}, bytesSpans(old), "the old array keeps its bits")
}

// TestCopiedBufferGrowSlide is the case of plan section 9.1 item 4: a value
// copy of a Buffer shares the array; a slide in one copy does not remove the
// taint that the other copy shows.
func TestCopiedBufferGrowSlide(t *testing.T) {
	a := begin(t)
	input := source(t, a, "q", "attack")
	var buffer bytes.Buffer
	buffer.Grow(64)
	c := cap(buffer.Bytes())
	require.Equal(t, 64, c)
	buffer.WriteString(strings.Repeat("p", 40))
	buffer.WriteString(input)
	copied := buffer
	buffer.Next(40)
	buffer.Write(make([]byte, 20)) // slide (see TestBufferCopyInteriorCompaction)
	require.Equal(t, c, cap(buffer.Bytes()))
	require.Equal(t, "attack", string(buffer.Bytes()[:6]))
	require.Equal(t, []span{{0, 6}}, bytesSpans(buffer.Bytes()))
	shown := copied.Bytes()
	require.Equal(t, "attack"+string(make([]byte, 20))+strings.Repeat("p", 14)+"attack", string(shown))
	require.Equal(t, []span{{0, 6}, {40, 46}}, bytesSpans(shown), "the copy sees the bits of the bytes that it shows")
}

func TestBufferTruncateAndString(t *testing.T) {
	a := begin(t)
	input := source(t, a, "q", "attack")
	var buffer bytes.Buffer
	buffer.WriteString(input)
	buffer.Truncate(2)
	got := buffer.String()
	require.Equal(t, "at", got)
	require.Equal(t, []span{{0, 2}}, stringSpans(got))
	require.Equal(t, []string{"0-2=q"}, attributed(t, a, got))
	buffer.Truncate(0)
	require.Empty(t, buffer.String())
	var nilBuffer *bytes.Buffer
	require.Equal(t, "<nil>", nilBuffer.String())
}

func TestBufferOriginalPanics(t *testing.T) {
	a := begin(t)
	_ = source(t, a, "q", "active")
	capture := func(fn func()) (result any) {
		defer func() { result = recover() }()
		fn()
		return nil
	}
	for name, fn := range map[string]func(){
		"truncate":       func() { var b bytes.Buffer; b.Truncate(-1) },
		"grow":           func() { var b bytes.Buffer; b.Grow(-1) },
		"nil-grow":       func() { var b *bytes.Buffer; b.Grow(1) },
		"nil-write":      func() { var b *bytes.Buffer; b.WriteString("hello") },
		"nil-writebyte":  func() { var b *bytes.Buffer; b.WriteByte('x') },
		"nil-writerune":  func() { var b *bytes.Buffer; b.WriteRune('界') },
		"negative-read":  func() { var b bytes.Buffer; b.ReadFrom(negativeReader{}) },
		"too-large-grow": func() { var b bytes.Buffer; b.WriteString("x"); b.Grow(int(^uint(0) >> 1)) },
	} {
		t.Run(name, func(t *testing.T) {
			got := capture(fn)
			require.NotNil(t, got)
			if name == "negative-read" {
				require.Equal(t, "bytes.Buffer: reader returned negative count from Read", fmt.Sprint(got))
			}
			if name == "too-large-grow" {
				require.Equal(t, bytes.ErrTooLarge, got)
			}
		})
	}
}

type negativeReader struct{}

func (negativeReader) Read([]byte) (int, error) { return -1, nil }

type bufferErrorReader struct{ err error }

func (r bufferErrorReader) Read(dst []byte) (int, error) {
	return copy(dst, "io"), r.err
}

// Deviation from TestBufferOriginalReadFromError (plan section 9.2): the
// earlier tainted bytes keep their exact bits.
func TestBufferOriginalReadFromError(t *testing.T) {
	a := begin(t)
	want := errors.New("reader failure")
	var buffer bytes.Buffer
	buffer.WriteString(source(t, a, "q", "attack"))
	n, err := buffer.ReadFrom(bufferErrorReader{want})
	require.Same(t, want, err)
	require.Equal(t, int64(2), n)
	got := buffer.String()
	require.Equal(t, "attackio", got)
	require.Equal(t, []span{{0, 6}}, stringSpans(got))
}

// taintingReader is a reader whose Read taints the bytes that it writes (as
// the request body source does).
type taintingReader struct {
	data   []string
	reads  int
	panics bool
}

func (r *taintingReader) Read(p []byte) (int, error) {
	if r.panics {
		panic("read failure")
	}
	if r.reads >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.reads])
	r.reads++
	if n > 0 {
		heapbits.SetBytes(p[:n])
	}
	return n, nil
}

// TestBufferReadFromReadRule checks the read rule of plan section 6.2: a
// read into reused memory leaves only the bits of the new data on the bytes
// that it wrote, and the tail keeps its old bits.
func TestBufferReadFromReadRule(t *testing.T) {
	a := begin(t)
	input := source(t, a, "q", strings.Repeat("A", 600))

	setup := func(t *testing.T) (*bytes.Buffer, []byte) {
		t.Helper()
		var buffer bytes.Buffer
		buffer.Grow(2048)
		buffer.WriteString(input)
		view := buffer.Bytes()[:600]
		buffer.Reset()
		require.Equal(t, []span{{0, 600}}, bytesSpans(view))
		return &buffer, view
	}

	t.Run("short read", func(t *testing.T) {
		buffer, view := setup(t)
		n, err := buffer.ReadFrom(strings.NewReader("clean"))
		require.NoError(t, err)
		require.Equal(t, int64(5), n)
		require.Equal(t, "cleanAAAAA", string(view[:10]))
		require.Equal(t, []span{{5, 600}}, bytesSpans(view), "clean written prefix, tainted tail")
		require.Empty(t, bytesSpans(buffer.Bytes()))
	})

	t.Run("zero read", func(t *testing.T) {
		buffer, view := setup(t)
		n, err := buffer.ReadFrom(strings.NewReader(""))
		require.NoError(t, err)
		require.Zero(t, n)
		require.Equal(t, []span{{0, 600}}, bytesSpans(view), "nothing written: the bits stay")
	})

	t.Run("tainted read", func(t *testing.T) {
		buffer, view := setup(t)
		n, err := buffer.ReadFrom(&taintingReader{data: []string{"0123", "4567"}})
		require.NoError(t, err)
		require.Equal(t, int64(8), n)
		require.Equal(t, "01234567", buffer.String())
		require.Equal(t, []span{{0, 600}}, bytesSpans(view))
		require.Equal(t, []span{{0, 8}}, bytesSpans(buffer.Bytes()))
	})

	t.Run("clean read after a tainted read", func(t *testing.T) {
		var buffer bytes.Buffer
		buffer.Grow(2048)
		_, err := buffer.ReadFrom(&taintingReader{data: []string{"tainted-body"}})
		require.NoError(t, err)
		require.Equal(t, []span{{0, 12}}, bytesSpans(buffer.Bytes()))
		buffer.Reset()
		_, err = buffer.ReadFrom(strings.NewReader("clean"))
		require.NoError(t, err)
		require.Equal(t, "clean", buffer.String())
		require.Empty(t, bytesSpans(buffer.Bytes()))
	})

	t.Run("a panicking reader", func(t *testing.T) {
		buffer, view := setup(t)
		require.PanicsWithValue(t, "read failure", func() {
			buffer.ReadFrom(&taintingReader{panics: true})
		})
		require.Equal(t, input, string(view), "the bytes do not change")
	})

	t.Run("grow during ReadFrom keeps the earlier bits", func(t *testing.T) {
		var buffer bytes.Buffer
		buffer.WriteString(input)
		_, err := buffer.ReadFrom(strings.NewReader(strings.Repeat("c", 4096)))
		require.NoError(t, err)
		require.Equal(t, []span{{0, 600}}, bytesSpans(buffer.Bytes()))
	})
}

// TestBufferResultsUnchanged checks that the Buffer hooks keep the results of
// a mix of operations.
func TestBufferResultsUnchanged(t *testing.T) {
	a := begin(t)
	tainted := source(t, a, "q", "attack-value")
	clean := strings.Clone("attack-value")
	run := func(s string) (string, int) {
		var b bytes.Buffer
		total := 0
		for i := range 50 {
			n, _ := b.WriteString(s)
			total += n
			b.WriteByte(byte('a' + i%26))
			n, _ = b.WriteRune('界')
			total += n
			n, _ = b.Write([]byte(s[:i%len(s)]))
			total += n
			if i%7 == 0 {
				b.Next(13)
			}
			if i%11 == 0 {
				m, _ := b.ReadFrom(strings.NewReader(s))
				total += int(m)
			}
		}
		return b.String(), total
	}
	gotValue, gotTotal := run(tainted)
	wantValue, wantTotal := run(clean)
	require.Equal(t, wantValue, gotValue)
	require.Equal(t, wantTotal, gotTotal)
	require.NotEmpty(t, stringSpans(gotValue))
	require.Empty(t, stringSpans(wantValue))
}
