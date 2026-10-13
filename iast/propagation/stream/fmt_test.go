// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package stream_test

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// errEOF is io.EOF (the body reader of helpers_test.go returns it).
var errEOF = io.EOF

// Plan section 9.2: the fmt buffer hooks copy the bytes exactly, thus the
// Sprint* results have exact ranges (PR #39: coarse ranges).
func TestFmtExactCopies(t *testing.T) {
	_, a := begin(t)
	v := param(t, a, "q", "robert")
	b := paramBytes(t, a, "b", "tables")
	for _, test := range []struct {
		name string
		got  string
		want [][2]int
		attr []string
	}{
		{"Sprint", fmt.Sprint("a=", v, "!"), [][2]int{{2, 8}}, []string{"2-8=" + paramLabel("q")}},
		{"Sprintf %s", fmt.Sprintf("id=%s;", v), [][2]int{{3, 9}}, []string{"3-9=" + paramLabel("q")}},
		{"Sprintf %v", fmt.Sprintf("<%v>", v), [][2]int{{1, 7}}, []string{"1-7=" + paramLabel("q")}},
		{"Sprintf %s of []byte", fmt.Sprintf("[%s]", b), [][2]int{{1, 7}}, []string{"1-7=" + paramLabel("b")}},
		{"Sprintf 2 sources", fmt.Sprintf("%s-%s", v, b), [][2]int{{0, 6}, {7, 13}}, []string{"0-6=" + paramLabel("q"), "7-13=" + paramLabel("b")}},
		{"Sprintf precision", fmt.Sprintf("%.3s", v), [][2]int{{0, 3}}, []string{"0-3=" + paramLabel("q")}},
		{"Sprintln", fmt.Sprintln(v, 42), [][2]int{{0, 6}}, []string{"0-6=" + paramLabel("q")}},
		{"Errorf", fmt.Errorf("bad user %s", v).Error(), [][2]int{{9, 15}}, []string{"9-15=" + paramLabel("q")}},
		{"Errorf %w", fmt.Errorf("x %s: %w", v, errors.New("inner")).Error(), [][2]int{{2, 8}}, []string{"2-8=" + paramLabel("q")}},
		{"nested struct %v", fmt.Sprintf("%v", struct{ A string }{v}), [][2]int{{1, 7}}, []string{"1-7=" + paramLabel("q")}},
		{"nested struct %+v", fmt.Sprintf("%+v", struct{ A string }{v}), [][2]int{{3, 9}}, []string{"3-9=" + paramLabel("q")}},
		{"slice %v", fmt.Sprintf("%v", []string{"x", v}), [][2]int{{3, 9}}, []string{"3-9=" + paramLabel("q")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, rangesString(test.got), "%q", test.got)
			require.Equal(t, test.attr, attributed(t, a, test.got))
		})
	}
}

// recorder is a writer that records the tainted ranges of each write.
type recorder struct {
	data   []byte
	ranges [][2]int
	// spare are the tainted ranges of the spare capacity of each write
	// (p[len(p):cap(p)]).
	spare [][2]int
}

func (w *recorder) Write(p []byte) (int, error) {
	for _, r := range rangesBytes(p) {
		w.ranges = append(w.ranges, [2]int{len(w.data) + r[0], len(w.data) + r[1]})
	}
	w.spare = append(w.spare, rangesBytes(p[len(p):cap(p)])...)
	w.data = append(w.data, p...)
	return len(p), nil
}

// The writer of Fprint* sees the exact bits of the printer buffer.
func TestFmtFprintfWriterSeesBits(t *testing.T) {
	_, a := begin(t)
	v := param(t, a, "q", "robert")
	var w recorder
	_, err := fmt.Fprintf(&w, "user=%s;", v)
	require.NoError(t, err)
	require.Equal(t, "user=robert;", string(w.data))
	require.Equal(t, [][2]int{{5, 11}}, w.ranges)
}

// badVerb is a variable: vet does not check it.
var badVerb = "x=%d;"

// Plan section 6.3 (round 3 M7): generated text of a tainted argument is
// tainted as a whole (coarse), and the derived entry gives its source.
func TestFmtGeneratedTextIsCoarse(t *testing.T) {
	_, a := begin(t)
	v := param(t, a, "q", "it's")
	b := paramBytes(t, a, "b", "\x01ab")
	for _, test := range []struct {
		name     string
		got      string
		from, to int // the span of the argument
		label    string
	}{
		{"%q", fmt.Sprintf("x=%q;", v), 2, 8, "q"},
		{"%x", fmt.Sprintf("x=%x;", v), 2, 10, "q"},
		{"%X", fmt.Sprintf("x=%X;", v), 2, 10, "q"},
		{"%#v", fmt.Sprintf("x=%#v;", v), 2, 8, "q"},
		{"%+q", fmt.Sprintf("x=%+q;", v), 2, 8, "q"},
		{"%#q", fmt.Sprintf("x=%#q;", v), 2, 8, "q"},
		{"bad verb", fmt.Sprintf(badVerb, v), 2, 2 + len("%!d(string=it's)"), "q"},
		{"[]byte %v", fmt.Sprintf("x=%v;", b), 2, 2 + len("[1 97 98]"), "b"},
		{"[]byte %d", fmt.Sprintf("x=%d;", b), 2, 2 + len("[1 97 98]"), "b"},
		{"[]byte %x", fmt.Sprintf("x=%x;", b), 2, 8, "b"},
		{"[]byte %q", fmt.Sprintf("x=%q;", b), 2, 2 + len(`"\x01ab"`), "b"},
		{"[]byte %#v", fmt.Sprintf("x=%#v;", b), 2, 2 + len("[]byte{0x1, 0x61, 0x62}"), "b"},
		{"nested %q", fmt.Sprintf("x=%q;", []string{v}), 3, 9, "q"},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, [][2]int{{test.from, test.to}}, rangesString(test.got), "%q", test.got)
			want := fmt.Sprintf("%d-%d=%s", test.from, test.to, paramLabel(test.label))
			require.Equal(t, []string{want}, attributed(t, a, test.got), "%q", test.got)
		})
	}
}

// Plan sections 6.3 and 9.1 item 4: %v and %d of a tainted []byte.
func TestFmtBytesDecimal(t *testing.T) {
	_, a := begin(t)
	b := paramBytes(t, a, "id", "12")
	got := fmt.Sprintf("SELECT %v", b)
	require.Equal(t, "SELECT [49 50]", got)
	require.Equal(t, [][2]int{{7, 14}}, rangesString(got))
	require.Equal(t, []string{"7-14=" + paramLabel("id")}, attributed(t, a, got))
}

// Plan sections 6.3 and 9.1 item 4: a tainted format string makes the whole
// output coarse.
func TestFmtTaintedFormat(t *testing.T) {
	_, a := begin(t)
	format := param(t, a, "f", "id=%d;")
	got := fmt.Sprintf(format, 42)
	require.Equal(t, "id=42;", got)
	require.Equal(t, [][2]int{{0, 6}}, rangesString(got))
	require.Equal(t, []string{"0-6=" + paramLabel("f")}, attributed(t, a, got))
	err := fmt.Errorf(format, 7)
	require.Equal(t, [][2]int{{0, 5}}, rangesString(err.Error()))
}

// Plan section 9.1 item 6 (round 3 M2): the padding growth keeps the bits of
// the old output; the padding is clean.
func TestFmtPaddingGrowth(t *testing.T) {
	_, a := begin(t)
	v := param(t, a, "q", "robert")
	got := fmt.Sprintf("%s%1000s", v, "x")
	require.Len(t, got, 1006)
	require.Equal(t, [][2]int{{0, 6}}, rangesString(got))
	require.Equal(t, []string{"0-6=" + paramLabel("q")}, attributed(t, a, got))

	got = fmt.Sprintf("%-10s|%10s", v, v)
	require.Equal(t, "robert    |    robert", got)
	require.Equal(t, [][2]int{{0, 6}, {15, 21}}, rangesString(got))

	got = fmt.Sprintf("%s%0300d", v, 5)
	require.Equal(t, [][2]int{{0, 6}}, rangesString(got))
}

type stringer string

var stringerCalls int

// String returns new memory with no bits (copy does not copy the bits).
func (s stringer) String() string {
	stringerCalls++
	b := make([]byte, len(s)+2)
	b[0] = '<'
	copy(b[1:], s)
	b[len(b)-1] = '>'
	return string(b)
}

type namedString string

type formatter []byte

var formatCalls int

func (f formatter) Format(s fmt.State, verb rune) {
	formatCalls++
	b := make([]byte, len(f))
	copy(b, f)
	_, _ = s.Write(b)
}

type failing string

func (failing) Error() string { return "fixed" }

// Plan section 9.1 item 6 (round 3 M7, round 4 item 2): %T, %p and the
// methods of a tainted argument: the output is coarse; the methods run once.
func TestFmtTypePointerAndMethods(t *testing.T) {
	_, a := begin(t)
	v := param(t, a, "q", "robert")
	b := paramBytes(t, a, "b", "tables")
	stringerCalls, formatCalls = 0, 0

	got := fmt.Sprintf("t=%T;", v)
	require.Equal(t, "t=string;", got)
	require.Equal(t, [][2]int{{2, 8}}, rangesString(got))
	require.Equal(t, []string{"2-8=" + paramLabel("q")}, attributed(t, a, got))

	got = fmt.Sprintf("p=%p;", b)
	require.Equal(t, [][2]int{{2, len(got) - 1}}, rangesString(got))
	require.Equal(t, []string{fmt.Sprintf("2-%d=%s", len(got)-1, paramLabel("b"))}, attributed(t, a, got))

	got = fmt.Sprintf("s=%s;", stringer(v))
	require.Equal(t, "s=<robert>;", got)
	require.Equal(t, 1, stringerCalls)
	require.Equal(t, [][2]int{{2, 10}}, rangesString(got))
	require.Equal(t, []string{"2-10=" + paramLabel("q")}, attributed(t, a, got))

	got = fmt.Sprint(stringer(v))
	require.Equal(t, 2, stringerCalls)
	require.Equal(t, [][2]int{{0, 8}}, rangesString(got))

	got = fmt.Sprintf("f=%v;", formatter(b))
	require.Equal(t, "f=tables;", got)
	require.Equal(t, 1, formatCalls)
	require.Equal(t, [][2]int{{2, 8}}, rangesString(got))
	require.Equal(t, []string{"2-8=" + paramLabel("b")}, attributed(t, a, got))

	// The output of Error is fixed text, but it is coarse: the argument is
	// tainted.
	got = fmt.Sprintf("e=%v;", failing(v))
	require.Equal(t, "e=fixed;", got)
	require.Equal(t, [][2]int{{2, 7}}, rangesString(got))

	// A named string with no method: %s is an exact copy, %q is generated.
	got = fmt.Sprintf("n=%s;", namedString(v))
	require.Equal(t, [][2]int{{2, 8}}, rangesString(got))
	got = fmt.Sprintf("n=%q;", namedString(v))
	require.Equal(t, [][2]int{{2, 10}}, rangesString(got))
}

// Plan section 6.3 (round 4 item 2): generated output gets the coarse entry
// of the argument's owner, also when the span already has bits of a
// different source.
func TestFmtMethodOutputOfOtherSource(t *testing.T) {
	_, a := begin(t)
	v := param(t, a, "q", "robert")
	other := param(t, a, "o", "tables")
	returnsOut = other
	got := fmt.Sprintf("%v", returns(v))
	require.Equal(t, "tables", got)
	require.Equal(t, [][2]int{{0, 6}}, rangesString(got))
	require.Contains(t, attributed(t, a, got)[0], "0-6=")
}

// returns is a named string type whose String method returns returnsOut (a
// different tainted value).
type returns string

var returnsOut string

func (returns) String() string { return returnsOut }

// Plan section 9.1 item 5: a clean %c after a tainted %q on the same printer
// has no taint (the scratch array intbuf never gets bits), and the printer
// buffer is clean when it goes back to the pool.
func TestFmtPrinterReuseIsClean(t *testing.T) {
	_, a := begin(t)
	v := param(t, a, "q", strings.Repeat("robert", 50))
	for range 100 {
		got := fmt.Sprintf("%q", v)
		require.Equal(t, [][2]int{{0, len(got)}}, rangesString(got))
		got = fmt.Sprintf("%c%c", 'x', 'y')
		require.Empty(t, rangesString(got))
		got = fmt.Sprintf("%5s|%d", heapString("ab"), 12)
		require.Empty(t, rangesString(got))
		var w recorder
		_, _ = fmt.Fprintf(&w, "%c", 'z')
		require.Empty(t, w.ranges)
		require.Empty(t, w.spare, "the printer buffer has old bits after its release")
	}
}

// The coarse rule with a forced GC and a stack growth in a method of the
// argument (plan section 6.1 rule 5).
func TestFmtCoarseWithGCAndStackGrowth(t *testing.T) {
	_, a := begin(t)
	v := param(t, a, "q", "robert")
	got := fmt.Sprintf("x=%v;", growing(v))
	require.Equal(t, "x=ROBERT;", got)
	require.Equal(t, [][2]int{{2, 8}}, rangesString(got))
	require.Equal(t, []string{"2-8=" + paramLabel("q")}, attributed(t, a, got))
}

type growing string

func (g growing) String() string {
	runtime.GC()
	deep(200)
	runtime.GC()
	b := make([]byte, len(g))
	for i := range len(g) {
		b[i] = g[i] - 'a' + 'A'
	}
	return string(b)
}

//go:noinline
func deep(n int) byte {
	var pad [256]byte
	if n == 0 {
		return pad[0]
	}
	pad[n%256] = byte(n)
	return deep(n-1) + pad[n%256]
}

// Concurrent formatting of tainted values (run with -race).
func TestFmtConcurrent(t *testing.T) {
	_, a := begin(t)
	v := param(t, a, "q", "robert")
	var wait sync.WaitGroup
	errs := make(chan string, 64)
	for range 8 {
		wait.Go(func() {
			for range 200 {
				got := fmt.Sprintf("id=%s;%q", v, v)
				if r := rangesString(got); len(r) != 2 || r[0] != [2]int{3, 9} || r[1] != [2]int{10, 18} {
					errs <- fmt.Sprintf("%q: %v", got, r)
					return
				}
			}
		})
	}
	wait.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// Clean values stay clean.
func TestFmtCleanValues(t *testing.T) {
	_, a := begin(t)
	_ = param(t, a, "q", "robert")
	got := fmt.Sprintf("%s|%q|%x|%v|%T", heapString("ab"), heapString("cd"), heapBytes("ef"), heapBytes("gh"), heapString("ij"))
	require.Empty(t, rangesString(got))
}
