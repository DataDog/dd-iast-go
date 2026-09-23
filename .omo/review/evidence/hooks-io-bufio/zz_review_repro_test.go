package io_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

func dumpRanges(data []byte) string {
	var out []string
	taint.VisitBytes(data, func(r taint.Range) bool {
		out = append(out, fmt.Sprintf("[%d,+%d origin=%v value=%q]", r.Start, r.Length, r.Source.Origin, r.Source.Value))
		return true
	})
	return strings.Join(out, " ")
}

// F: MultiReader(clean, bound) -> io.ReadAll taints the clean prefix and records it as body source value.
func TestReviewMultiReaderCleanPrefixTainted(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("needs orchestrion")
	}
	ctx, _ := activeContext(t)
	body := strings.NewReader("1 OR 1=1")
	request.BindReader(ctx, body)
	data, _ := io.ReadAll(io.MultiReader(strings.NewReader("SELECT * FROM t WHERE id = "), body))
	t.Logf("case=mixed data=%q ranges=%s", data, dumpRanges(data))

	ctx2, _ := activeContext(t)
	empty := strings.NewReader("")
	request.BindReader(ctx2, empty)
	clean, _ := io.ReadAll(io.MultiReader(strings.NewReader("SELECT * FROM t WHERE id = 1"), empty))
	t.Logf("case=bound-empty data=%q tainted=%v ranges=%s", clean, taint.IsTaintedBytes(clean), dumpRanges(clean))
}

// F: bufio.Reader.Reset / LimitedReader.R keep the stale reader binding.
func TestReviewStaleBindingAfterReset(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("needs orchestrion")
	}
	ctx, _ := activeContext(t)
	body := strings.NewReader("request-body")
	request.BindReader(ctx, body)
	br := bufio.NewReader(body)
	br.Reset(strings.NewReader("SELECT 1 FROM clean_constant"))
	data, _ := io.ReadAll(br)
	t.Logf("case=bufio.Reset data=%q tainted=%v ranges=%s", data, taint.IsTaintedBytes(data), dumpRanges(data))

	lr := io.LimitReader(body, 1024).(*io.LimitedReader)
	lr.R = strings.NewReader("SELECT 2 FROM clean_constant")
	data2, _ := io.ReadAll(lr)
	t.Logf("case=LimitedReader.R data=%q tainted=%v ranges=%s", data2, taint.IsTaintedBytes(data2), dumpRanges(data2))
}

// F: a reader bound by request A and Reset by request B attributes B's data to A.
func TestReviewCrossOwnerViaResetReader(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("needs orchestrion")
	}
	ctxA, scopeA := activeContext(t)
	_, scopeB := activeContext(t)
	bodyA := strings.NewReader("body-of-A")
	request.BindReader(ctxA, bodyA)
	pooled := bufio.NewReader(bodyA) // created in A, later reused (e.g. sync.Pool)
	_, _ = io.ReadAll(pooled)
	aBefore, _ := scopeA.Analysis()
	before := aBefore.SourceCount()

	// Request B (unrelated owner) reuses the reader for its own clean data.
	pooled.Reset(strings.NewReader("SELECT 3 FROM data_of_B"))
	dataB, _ := io.ReadAll(pooled)
	aAfter, _ := scopeA.Analysis()
	bAn, _ := scopeB.Analysis()
	t.Logf("case=cross-owner dataB=%q tainted=%v ranges=%s ownerA.sources before=%d after=%d ownerB.sources=%d",
		dataB, taint.IsTaintedBytes(dataB), dumpRanges(dataB), before, aAfter.SourceCount(), bAn.SourceCount())
}

type nErrReader struct {
	chunks [][]byte
	err    error
}

func (r *nErrReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks[0] = r.chunks[0][n:]
	if len(r.chunks[0]) == 0 {
		r.chunks = r.chunks[1:]
		if len(r.chunks) == 0 && r.err != nil {
			return n, r.err
		}
	}
	return n, nil
}

type panicReader struct{ after int }

func (r *panicReader) Read(p []byte) (int, error) {
	if r.after == 0 {
		panic("reader-panic")
	}
	r.after--
	p[0] = 'x'
	return 1, nil
}

type oneByte struct{ r io.Reader }

func (o oneByte) Read(p []byte) (int, error) { return o.r.Read(p[:min(1, len(p))]) }

var errCustom = errors.New("custom")

// Parity: printed digests must be identical with and without orchestrion.
func TestReviewParity(t *testing.T) {
	ctx, _ := activeContext(t)
	big := bytes.Repeat([]byte("abcdefgh"), 100*1024/8)
	mk := func(bind bool, r io.Reader) io.Reader {
		if bind {
			request.BindReader(ctx, r)
		}
		return r
	}
	for _, bind := range []bool{false, true} {
		cases := map[string]func() io.Reader{
			"n+err":      func() io.Reader { return mk(bind, &nErrReader{chunks: [][]byte{[]byte("ab"), []byte("cdef")}, err: errCustom}) },
			"n+eof":      func() io.Reader { return mk(bind, &nErrReader{chunks: [][]byte{[]byte("abcdef")}, err: io.EOF}) },
			"onebyte":    func() io.Reader { return oneByte{mk(bind, strings.NewReader("one-byte-at-a-time"))} },
			"big":        func() io.Reader { return mk(bind, bytes.NewReader(big)) },
			"limit":      func() io.Reader { return io.LimitReader(mk(bind, bytes.NewReader(big)), 70000) },
			"limit0":     func() io.Reader { return io.LimitReader(mk(bind, strings.NewReader("abc")), 0) },
			"limitneg":   func() io.Reader { return io.LimitReader(mk(bind, strings.NewReader("abc")), -5) },
			"multi-nil":  func() io.Reader { return io.MultiReader() },
			"multi":      func() io.Reader { return io.MultiReader(strings.NewReader("x"), mk(bind, strings.NewReader("yz")), &nErrReader{chunks: [][]byte{[]byte("w")}, err: errCustom}) },
			"tee":        func() io.Reader { var b bytes.Buffer; return io.TeeReader(mk(bind, strings.NewReader("teedata")), &b) },
			"bufio16":    func() io.Reader { return bufio.NewReaderSize(mk(bind, bytes.NewReader(big)), 1) },
			"bufio-self": func() io.Reader { b := bufio.NewReaderSize(mk(bind, strings.NewReader("self")), 64); return bufio.NewReaderSize(b, 32) },
		}
		for _, name := range []string{"n+err", "n+eof", "onebyte", "big", "limit", "limit0", "limitneg", "multi-nil", "multi", "tee", "bufio16", "bufio-self"} {
			data, err := io.ReadAll(cases[name]())
			sum := sha256.Sum256(data)
			t.Logf("PARITY bind=%v %s len=%d cap=%d nil=%v sha=%x err=%v", bind, name, len(data), cap(data), data == nil, sum[:6], err)
		}
		func() {
			defer func() { t.Logf("PARITY bind=%v panic recovered=%v", bind, recover()) }()
			_, _ = io.ReadAll(mk(bind, &panicReader{after: 3}))
		}()
		func() {
			defer func() { t.Logf("PARITY bind=%v nilreader recovered=%v", bind, recover() != nil) }()
			_, _ = io.ReadAll(nil)
		}()
		br := bufio.NewReaderSize(mk(bind, strings.NewReader("line1\nline2")), 16)
		p, perr := br.Peek(3)
		s, serr := br.ReadString('\n')
		t.Logf("PARITY bind=%v peek=%q/%v rs=%q/%v peekTainted=%v rsTainted=%v", bind, p, perr, s, serr, taint.IsTaintedBytes(p), taint.IsTaintedString(s))
	}
}
