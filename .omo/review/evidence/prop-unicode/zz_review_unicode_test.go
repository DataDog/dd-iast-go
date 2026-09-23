// Review reproducer (prop-unicode): differential per-byte provenance oracle for
// length-changing transformations. Not part of the product.

package propagation_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
	"unsafe"

	iastprop "github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

// label 0 = clean, otherwise source id.
type labels []ranges.SourceID

var unicodeTokens = []string{
	"a", "Z", "i", "k", "s", "ẞ", "ß", "İ", "ı", "ɐ", "Ɐ", "ɑ", "Ɑ", "\u212a", "\u212b", "ǅ", "ﬁ", "ΐ", "ſ",
	"\xff", "\xc0", "\xe2\x82", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xef\xbf\xbd", "\xf0\x9f\x98",
	"%", "%2", "%zz", "%41", "%e2%82%ac", "+", " ", "\\", "\"", "'", "`", "\n", "\r", "\t", "\x00", "\x7f",
	"é", "日", "😀", "/", "?", "&", "=", "SELECT", "abc", "ABC", "\u0345", "\u1e9e", "\u2c65", "\u023a",
}

type unicodeHarness struct {
	t       *testing.T
	s       *store.Store
	owner   *store.Owner
	rng     *rand.Rand
	fails   int
	cases   int
	tainted map[string]int
}

func (h *unicodeHarness) randomInput() string {
	var b strings.Builder
	n := 1 + h.rng.Intn(10)
	for range n {
		b.WriteString(unicodeTokens[h.rng.Intn(len(unicodeTokens))])
	}
	return b.String()
}

// randomLabels splits value into up to 5 byte pieces (possibly mid-rune) and
// labels each piece clean or with a source in [base, base+3].
func (h *unicodeHarness) randomLabels(length int, base ranges.SourceID) labels {
	out := make(labels, length)
	if length == 0 {
		return out
	}
	cuts := []int{0, length}
	for range h.rng.Intn(5) {
		cuts = append(cuts, h.rng.Intn(length+1))
	}
	slices.Sort(cuts)
	cuts = slices.Compact(cuts)
	for i := 0; i+1 < len(cuts); i++ {
		var l ranges.SourceID
		if h.rng.Intn(4) != 0 {
			l = base + ranges.SourceID(h.rng.Intn(3))
		}
		for p := cuts[i]; p < cuts[i+1]; p++ {
			out[p] = l
		}
	}
	return out
}

func labelRanges(l labels) []ranges.Range {
	var out []ranges.Range
	for p := 0; p < len(l); {
		if l[p] == 0 {
			p++
			continue
		}
		e := p + 1
		for e < len(l) && l[e] == l[p] {
			e++
		}
		out = append(out, ranges.Range{Start: uint32(p), Length: uint32(e - p), SourceID: l[p]})
		p = e
	}
	return out
}

func (h *unicodeHarness) taintStr(value string, l labels) string {
	clone := strings.Clone(value)
	rs := labelRanges(l)
	if len(rs) == 0 || len(clone) < 2 {
		return clone
	}
	var set ranges.Set
	if !ranges.AdoptCanonical(&set, ranges.DefaultLimit, rs, uint32(len(clone))).Valid {
		h.t.Fatalf("bad ranges")
	}
	if _, ok := h.owner.AdoptString(clone, &set); !ok {
		h.t.Fatalf("adopt failed")
	}
	return clone
}

func (h *unicodeHarness) taintBytes(value []byte, l labels) []byte {
	clone := make([]byte, len(value))
	copy(clone, value)
	rs := labelRanges(l)
	if len(rs) == 0 || len(clone) < 2 {
		return clone
	}
	var set ranges.Set
	if !ranges.AdoptCanonical(&set, ranges.DefaultLimit, rs, uint32(cap(clone))).Valid {
		h.t.Fatalf("bad ranges")
	}
	if _, ok := h.owner.AdoptBytes(clone, &set); !ok {
		h.t.Fatalf("adopt failed")
	}
	return clone
}

// effective returns labels actually visible on a tainted input (roots < 2 bytes
// are never tainted).
func effective(value int, l labels) labels {
	if value < 2 {
		return make(labels, value)
	}
	return l
}

func (h *unicodeHarness) observe(key store.Key, ok bool, length int) (labels, string) {
	out := make(labels, length)
	if !ok {
		return out, ""
	}
	var snap store.Snapshot
	if !h.s.Lookup(key, &snap) {
		return out, "lookup contended"
	}
	idx, _ := h.owner.Index()
	for i := 0; i < snap.Len(); i++ {
		e, _ := snap.At(i)
		if e.OwnerIndex != idx || e.OwnerGen != h.owner.Generation() || e.OwnerID != h.owner.ID() {
			continue
		}
		for j := 0; j < e.Ranges.Len(); j++ {
			r, _ := e.Ranges.At(j)
			end := uint64(r.Start) + uint64(r.Length)
			if end > uint64(length) || r.Length == 0 {
				return out, fmt.Sprintf("OUT-OF-BOUNDS range %+v for len %d", r, length)
			}
			for p := r.Start; p < uint32(end); p++ {
				if out[p] != 0 {
					return out, "overlap"
				}
				out[p] = r.SourceID
			}
		}
	}
	return out, ""
}

// truncateRuns keeps the first `limit` maximal tainted runs.
func truncateRuns(l labels, limit int) labels {
	out := slices.Clone(l)
	runs := 0
	for p := 0; p < len(out); {
		if out[p] == 0 {
			p++
			continue
		}
		e := p + 1
		for e < len(out) && out[e] == out[p] {
			e++
		}
		if runs >= limit {
			for q := p; q < len(out); q++ {
				out[q] = 0
			}
			break
		}
		runs++
		p = e
	}
	return out
}

func coarseLabels(length int, inputs ...labels) labels {
	out := make(labels, length)
	for _, in := range inputs {
		for _, v := range in {
			if v != 0 {
				for i := range out {
					out[i] = v
				}
				return out
			}
		}
	}
	return out
}

type expectation int

const (
	expectExact expectation = iota
	expectCoarse
)

func (h *unicodeHarness) check(op string, input any, want labels, got labels, problem string, wantValue, gotValue any) {
	h.cases++
	opName, _, _ := strings.Cut(op, "(")
	for _, v := range want {
		if v != 0 {
			h.tainted[opName]++
			break
		}
	}
	if problem != "" || !slices.Equal(want, got) || fmt.Sprint(wantValue) != fmt.Sprint(gotValue) {
		h.fails++
		if h.fails <= 40 {
			h.t.Errorf("%s input=%q\n  wantValue=%q gotValue=%q\n  want=%v\n  got =%v %s", op, input, wantValue, gotValue, want, got, problem)
		}
	}
}

func stringAliasOffset(input, result string) (int, bool) {
	if len(input) == 0 || len(result) == 0 {
		return 0, false
	}
	b := uintptr(unsafe.Pointer(unsafe.StringData(input)))
	p := uintptr(unsafe.Pointer(unsafe.StringData(result)))
	if p >= b && p+uintptr(len(result)) <= b+uintptr(len(input)) {
		return int(p - b), true
	}
	return 0, false
}

// expectedFromAliasOrFresh computes expected labels: alias => window, fresh
// result shorter than 2 bytes => clean, else exact or coarse oracle.
func expectedString(input string, inL labels, result string, exact labels, mode expectation, coarseInputs ...labels) labels {
	if off, ok := stringAliasOffset(input, result); ok {
		return slices.Clone(inL[off : off+len(result)])
	}
	if len(result) < 2 {
		return make(labels, len(result))
	}
	if mode == expectCoarse {
		return coarseLabels(len(result), coarseInputs...)
	}
	return truncateRuns(exact, int(ranges.DefaultLimit))
}

// oracleReplace mirrors strings.Replace semantics while carrying labels.
func oracleReplace(s string, sl labels, old, repl string, rl labels, n int) (string, labels, int) {
	return oracleReplaceMode(s, sl, old, repl, rl, n, true)
}

func oracleReplaceMode(s string, sl labels, old, repl string, rl labels, n int, stringsMode bool) (string, labels, int) {
	if stringsMode && old == repl || n == 0 {
		return s, sl, 0
	}
	m := strings.Count(s, old)
	if m == 0 {
		return s, sl, 0
	}
	if n < 0 || m < n {
		n = m
	}
	var out []byte
	var ol labels
	start := 0
	for i := 0; i < n; i++ {
		j := start
		if len(old) == 0 {
			if i > 0 {
				_, w := utf8.DecodeRuneInString(s[start:])
				j += w
			}
		} else {
			j += strings.Index(s[start:], old)
		}
		out = append(out, s[start:j]...)
		ol = append(ol, sl[start:j]...)
		out = append(out, repl...)
		ol = append(ol, rl...)
		start = j + len(old)
	}
	out = append(out, s[start:]...)
	ol = append(ol, sl[start:]...)
	return string(out), ol, n
}

// oracleValidUTF8 mirrors bytes.ToValidUTF8 while carrying labels.
func oracleValidUTF8(s []byte, sl labels, repl []byte, rl labels) ([]byte, labels, int) {
	var out []byte
	var ol labels
	runs := 0
	invalid := false
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			out = append(out, c)
			ol = append(ol, sl[i])
			i++
			invalid = false
			continue
		}
		_, w := utf8.DecodeRune(s[i:])
		if w == 1 {
			if !invalid {
				invalid = true
				runs++
				out = append(out, repl...)
				ol = append(ol, rl...)
			}
			i++
			continue
		}
		invalid = false
		out = append(out, s[i:i+w]...)
		ol = append(ol, sl[i:i+w]...)
		i += w
	}
	return out, ol, runs
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

var mappings = []struct {
	name string
	fn   func(rune) rune
}{
	{"identity", func(r rune) rune { return r }},
	{"upper", unicode.ToUpper},
	{"lower", unicode.ToLower},
	{"title", unicode.ToTitle},
	{"dropA", func(r rune) rune {
		if r == 'a' || r == 'Z' {
			return -1
		}
		return r
	}},
	{"expand", func(r rune) rune {
		if r < 0x80 {
			return '😀'
		}
		return r
	}},
	{"shrink", func(r rune) rune {
		if r >= 0x80 {
			return 'x'
		}
		return r
	}},
	{"surrogate", func(r rune) rune { return 0xD800 }},
	{"toobig", func(r rune) rune { return 0x110000 }},
	{"dropMulti", func(r rune) rune {
		if r >= 0x80 {
			return -1
		}
		return r
	}},
}

func (h *unicodeHarness) oldFor(s string) string {
	switch h.rng.Intn(4) {
	case 0:
		return ""
	case 1:
		return unicodeTokens[h.rng.Intn(len(unicodeTokens))]
	default:
		if len(s) == 0 {
			return "a"
		}
		i := h.rng.Intn(len(s))
		j := i + 1 + h.rng.Intn(min(3, len(s)-i))
		return s[i:j] // may split a rune
	}
}

func (h *unicodeHarness) iteration() {
	raw := h.randomInput()
	inL := h.randomLabels(len(raw), 1)
	input := h.taintStr(raw, inL)
	inL = effective(len(input), inL)

	rawRepl := unicodeTokens[h.rng.Intn(len(unicodeTokens))]
	if h.rng.Intn(3) == 0 {
		rawRepl = ""
	}
	var replL labels
	if h.rng.Intn(2) == 0 {
		replL = make(labels, len(rawRepl))
		for i := range replL {
			replL[i] = 9
		}
	} else {
		replL = make(labels, len(rawRepl))
	}
	repl := h.taintStr(rawRepl, replL)
	replL = effective(len(repl), replL)

	// strings.Replace / ReplaceAll
	old := h.oldFor(input)
	n := []int{-1, 0, 1, 2, 3, 40}[h.rng.Intn(6)]
	wantV, exactL, matches := oracleReplace(input, inL, old, repl, replL, n)
	got := iastprop.StringsReplace(input, old, repl, n)
	mode := expectExact
	if matches > 32 {
		mode = expectCoarse
	}
	gotL, prob := h.observeString(got)
	h.check(fmt.Sprintf("strings.Replace(old=%q,new=%q,n=%d)", old, repl, n), input,
		expectedString(input, inL, got, exactL, mode, inL, replL), gotL, prob, wantV, got)

	// bytes.Replace
	bIn := h.taintBytes([]byte(raw), effective(len(raw), inL))
	bRepl := h.taintBytes([]byte(rawRepl), replL)
	wantV, exactL, matches = oracleReplaceMode(raw, inL, old, rawRepl, replL, n, false)
	gotB := iastprop.BytesReplace(bIn, []byte(old), bRepl, n)
	mode = expectExact
	if matches > 32 {
		mode = expectCoarse
	}
	gotL, prob = h.observeBytes(gotB)
	h.check(fmt.Sprintf("bytes.Replace(old=%q,new=%q,n=%d)", old, rawRepl, n), raw,
		expectedBytes(gotB, exactL, mode, inL, replL), gotL, prob, wantV, string(gotB))

	// bytes.ToValidUTF8
	wantBV, exactL, runs := oracleValidUTF8(bIn, inL, bRepl, replL)
	gotB = iastprop.BytesToValidUTF8(bIn, bRepl)
	mode = expectExact
	if runs > 32 {
		mode = expectCoarse
	}
	gotL, prob = h.observeBytes(gotB)
	h.check(fmt.Sprintf("bytes.ToValidUTF8(repl=%q)", rawRepl), raw,
		expectedBytes(gotB, exactL, mode, inL, replL), gotL, prob, string(wantBV), string(gotB))

	// strings.ToValidUTF8: coarse over value (+replacement when used).
	wantS := strings.ToValidUTF8(input, repl)
	got = iastprop.StringsToValidUTF8(input, repl)
	gotL, prob = h.observeString(got)
	_, _, sruns := oracleValidUTF8([]byte(input), inL, []byte(repl), replL)
	coarseIn := []labels{inL}
	if sruns > 0 {
		coarseIn = append(coarseIn, replL)
	}
	h.check(fmt.Sprintf("strings.ToValidUTF8(repl=%q)", repl), input,
		expectedString(input, inL, got, nil, expectCoarse, coarseIn...), gotL, prob, wantS, got)

	// Case transforms.
	for _, c := range []struct {
		name string
		sfn  func(string) string
		std  func(string) string
		bfn  func([]byte) []byte
	}{
		{"ToUpper", iastprop.StringsToUpper, strings.ToUpper, iastprop.BytesToUpper},
		{"ToLower", iastprop.StringsToLower, strings.ToLower, iastprop.BytesToLower},
		{"ToTitle", iastprop.StringsToTitle, strings.ToTitle, iastprop.BytesToTitle},
	} {
		wantS := c.std(input)
		got := c.sfn(input)
		m := expectCoarse
		if isASCII(input) && len(wantS) == len(input) {
			m = expectExact
		}
		gotL, prob := h.observeString(got)
		h.check("strings."+c.name, input, expectedString(input, inL, got, inL, m, inL), gotL, prob, wantS, got)

		gotB := c.bfn(bIn)
		gotL, prob = h.observeBytes(gotB)
		h.check("bytes."+c.name, raw, expectedBytes(gotB, inL, m, inL), gotL, prob, wantS, string(gotB))
	}

	// Map.
	mp := mappings[h.rng.Intn(len(mappings))]
	wantS = strings.Map(mp.fn, input)
	got = iastprop.StringsMap(mp.fn, input)
	gotL, prob = h.observeString(got)
	h.check("strings.Map/"+mp.name, input, expectedString(input, inL, got, nil, expectCoarse, inL), gotL, prob, wantS, got)
	gotB = iastprop.BytesMap(mp.fn, bIn)
	gotL, prob = h.observeBytes(gotB)
	h.check("bytes.Map/"+mp.name, raw, expectedBytes(gotB, nil, expectCoarse, inL), gotL, prob, wantS, string(gotB))

	// Escapes (coarse, or exact window on alias).
	type esc struct {
		name string
		fn   func(string) string
		std  func(string) string
	}
	unq := func(f func(string) (string, error)) func(string) string {
		return func(s string) string { r, err := f(s); return r + "|" + fmt.Sprint(err) }
	}
	for _, e := range []esc{
		{"QueryEscape", iastprop.URLQueryEscape, url.QueryEscape},
		{"PathEscape", iastprop.URLPathEscape, url.PathEscape},
		{"Quote", iastprop.StrconvQuote, strconv.Quote},
		{"QuoteToASCII", iastprop.StrconvQuoteToASCII, strconv.QuoteToASCII},
		{"QuoteToGraphic", iastprop.StrconvQuoteToGraphic, strconv.QuoteToGraphic},
	} {
		want := e.std(input)
		got := e.fn(input)
		gotL, prob := h.observeString(got)
		h.check(e.name, input, expectedString(input, inL, got, nil, expectCoarse, inL), gotL, prob, want, got)
	}
	for _, e := range []struct {
		name string
		fn   func(string) (string, error)
		std  func(string) (string, error)
	}{
		{"QueryUnescape", iastprop.URLQueryUnescape, url.QueryUnescape},
		{"PathUnescape", iastprop.URLPathUnescape, url.PathUnescape},
		{"Unquote", iastprop.StrconvUnquote, strconv.Unquote},
	} {
		in := input
		inLL := inL
		if e.name == "Unquote" {
			q := []string{"\"", "`", "'"}[h.rng.Intn(3)]
			wrapped := q + raw + q
			wl := append(append(labels{inL0(inL)}, inL...), inL0(inL))
			in = h.taintStr(wrapped, wl)
			inLL = effective(len(in), wl)
		}
		want := unq(e.std)(in)
		gotR, gotErr := e.fn(in)
		gotL, prob := h.observeString(gotR)
		h.check(e.name, in, expectedString(in, inLL, gotR, nil, expectCoarse, inLL), gotL, prob, want, gotR+"|"+fmt.Sprint(gotErr))
	}

	// Repeat / Join exact.
	cnt := h.rng.Intn(4)
	wantS = strings.Repeat(input, cnt)
	got = iastprop.StringsRepeat(input, cnt)
	var rl labels
	for range cnt {
		rl = append(rl, inL...)
	}
	gotL, prob = h.observeString(got)
	h.check(fmt.Sprintf("strings.Repeat(%d)", cnt), input, expectedString(input, inL, got, rl, expectExact), gotL, prob, wantS, got)

	elems := []string{input, repl, input}
	sep := unicodeTokens[h.rng.Intn(len(unicodeTokens))]
	wantS = strings.Join(elems, sep)
	got = iastprop.StringsJoin(elems, sep)
	sepL := make(labels, len(sep))
	jl := slices.Concat(inL, sepL, replL, sepL, inL)
	gotL, prob = h.observeString(got)
	h.check("strings.Join", input, expectedString("", nil, got, jl, expectExact), gotL, prob, wantS, got)
}

func inL0(l labels) ranges.SourceID {
	if len(l) == 0 {
		return 0
	}
	return l[0]
}

func expectedBytes(result []byte, exact labels, mode expectation, coarseInputs ...labels) labels {
	if len(result) < 2 {
		return make(labels, len(result))
	}
	if mode == expectCoarse {
		return coarseLabels(len(result), coarseInputs...)
	}
	return truncateRuns(exact, int(ranges.DefaultLimit))
}

func (h *unicodeHarness) observeString(v string) (labels, string) {
	k, ok := store.StringKey(v)
	return h.observe(k, ok, len(v))
}

func (h *unicodeHarness) observeBytes(v []byte) (labels, string) {
	k, ok := store.BytesKey(v)
	return h.observe(k, ok, len(v))
}

func TestReviewUnicodeDifferential(t *testing.T) {
	s, _ := beginScope(t)
	iterations := 20000
	if v := os.Getenv("REVIEW_ITER"); v != "" {
		iterations, _ = strconv.Atoi(v)
	}
	seed := int64(1)
	if v := os.Getenv("REVIEW_SEED"); v != "" {
		seed, _ = strconv.ParseInt(v, 10, 64)
	}
	h := &unicodeHarness{t: t, s: s, rng: rand.New(rand.NewSource(seed)), tainted: map[string]int{}}
	for i := 0; i < iterations; i++ {
		owner := s.Acquire()
		if owner.Disabled() {
			t.Fatalf("owner disabled")
		}
		h.owner = owner
		h.iteration()
		owner.Finish()
	}
	t.Logf("seed=%d cases=%d failures=%d", seed, h.cases, h.fails)
	keys := make([]string, 0, len(h.tainted))
	for k := range h.tainted {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		t.Logf("tainted-expected %-28s %d", k, h.tainted[k])
	}
	_ = bytes.Equal
}

func TestReviewUnicodeBoundaries(t *testing.T) {
	s, _ := beginScope(t)
	h := &unicodeHarness{t: t, s: s, rng: rand.New(rand.NewSource(7)), tainted: map[string]int{}}
	for _, runs := range []int{1, 31, 32, 33, 40} {
		for _, unit := range []string{"a\xff", "é\xff\xfe", "\xed\xa0\x80b", "日\xf0\x9f\x98x"} {
			owner := s.Acquire()
			h.owner = owner
			raw := strings.Repeat(unit, runs)
			inL := make(labels, len(raw))
			for i := range inL {
				inL[i] = ranges.SourceID(1 + (i/len(unit))%2)
			}
			inL = truncateRuns(inL, int(ranges.DefaultLimit))
			bIn := h.taintBytes([]byte(raw), inL)
			for _, rawRepl := range []string{"", "?", "\uFFFD", "REPLACEMENT"} {
				replL := make(labels, len(rawRepl))
				for i := range replL {
					replL[i] = 9
				}
				bRepl := h.taintBytes([]byte(rawRepl), effective(len(rawRepl), replL))
				replL = effective(len(rawRepl), replL)
				want, exactL, r := oracleValidUTF8(bIn, inL, bRepl, replL)
				got := iastprop.BytesToValidUTF8(bIn, bRepl)
				mode := expectExact
				if r > 32 {
					mode = expectCoarse
				}
				gotL, prob := h.observeBytes(got)
				h.check(fmt.Sprintf("bytes.ToValidUTF8(runs=%d,repl=%q)", r, rawRepl), raw, expectedBytes(got, exactL, mode, inL, replL), gotL, prob, string(want), string(got))

				// Replace every occurrence of the invalid byte run's first byte class.
				input := h.taintStr(raw, inL)
				for _, old := range []string{"\xff", "a", "\xed", ""} {
					for _, n := range []int{-1, 31, 32, 33} {
						wantS, exactS, m := oracleReplace(input, inL, old, rawRepl, replL, n)
						repl := h.taintStr(rawRepl, replL)
						gotS := iastprop.StringsReplace(input, old, repl, n)
						mode := expectExact
						if m > 32 {
							mode = expectCoarse
						}
						gotL, prob := h.observeString(gotS)
						h.check(fmt.Sprintf("strings.Replace(old=%q,n=%d,m=%d)", old, n, m), input[:min(len(input), 20)],
							expectedString(input, inL, gotS, exactS, mode, inL, replL), gotL, prob, wantS, gotS)
						wantB, exactB, mb := oracleReplaceMode(raw, inL, old, rawRepl, replL, n, false)
						gotB := iastprop.BytesReplace(bIn, []byte(old), bRepl, n)
						mode = expectExact
						if mb > 32 {
							mode = expectCoarse
						}
						gotL, prob = h.observeBytes(gotB)
						h.check(fmt.Sprintf("bytes.Replace(old=%q,n=%d,m=%d)", old, n, mb), raw[:min(len(raw), 20)],
							expectedBytes(gotB, exactB, mode, inL, replL), gotL, prob, wantB, string(gotB))
					}
				}
			}
			owner.Finish()
		}
	}
	// MaxRootBytes boundary for case conversion (ASCII exact, non-ASCII coarse).
	for _, size := range []int{store.MaxRootBytes - 1, store.MaxRootBytes, store.MaxRootBytes + 1} {
		for _, unit := range []string{"a", "\u212a"} {
			owner := s.Acquire()
			h.owner = owner
			raw := strings.Repeat(unit, size/len(unit)+1)[:size]
			raw = strings.ToValidUTF8(raw, "a")
			if len(raw) > size {
				raw = raw[:size]
			}
			if len(raw) > store.MaxRootBytes {
				owner.Finish()
				continue
			}
			inL := make(labels, len(raw))
			for i := range inL {
				inL[i] = ranges.SourceID(1 + (i/7)%2)
			}
			inL = truncateRuns(inL, int(ranges.DefaultLimit))
			input := h.taintStr(raw, inL)
			got := iastprop.StringsToLower(input)
			want := strings.ToLower(input)
			var exp labels
			if len(want) > store.MaxRootBytes {
				exp = make(labels, len(want))
			} else if isASCII(input) {
				exp = expectedString(input, inL, got, inL, expectExact, inL)
			} else {
				exp = expectedString(input, inL, got, nil, expectCoarse, inL)
			}
			gotL, prob := h.observeString(got)
			h.check(fmt.Sprintf("strings.ToLower(size=%d,unit=%q)", len(raw), unit), "<large>", exp, gotL, prob, len(want), len(got))
			owner.Finish()
		}
	}
	t.Logf("boundary cases=%d failures=%d tainted=%v", h.cases, h.fails, h.tainted)
}

func TestReviewCaseCoarsensWholeQuery(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	h := &unicodeHarness{t: t, s: s, owner: owner, tainted: map[string]int{}}
	for _, name := range []string{"bob", "josé"} {
		query := "select * from users where name = '" + name + "' and org = 'acme'"
		start := strings.Index(query, name)
		l := make(labels, len(query))
		for i := start; i < start+len(name); i++ {
			l[i] = 1
		}
		orgStart := strings.Index(query, "acme")
		for i := orgStart; i < orgStart+4; i++ {
			l[i] = 2
		}
		input := h.taintStr(query, l)
		got := iastprop.StringsToUpper(input)
		k, _ := store.StringKey(got)
		var snap store.Snapshot
		s.Lookup(k, &snap)
		e, _ := snap.At(0)
		out := make([]ranges.Range, e.Ranges.Len())
		e.Ranges.CopyTo(out)
		t.Logf("name=%q input ranges=%v -> ToUpper ranges=%v (len=%d)", name, labelRanges(l), out, len(got))
	}
}

func TestReviewToValidUTF8StringVsBytes(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	h := &unicodeHarness{t: t, s: s, owner: owner, tainted: map[string]int{}}
	query := "select * from users where name = 'bob\xff' and org = 'acme'"
	l := make(labels, len(query))
	for i := 34; i < 38; i++ {
		l[i] = 1
	}
	org := strings.Index(query, "acme")
	for i := org; i < org+4; i++ {
		l[i] = 2
	}
	input := h.taintStr(query, l)
	bInput := h.taintBytes([]byte(query), l)
	gs := iastprop.StringsToValidUTF8(input, "?")
	gb := iastprop.BytesToValidUTF8(bInput, []byte("?"))
	sl, _ := h.observeString(gs)
	bl, _ := h.observeBytes(gb)
	t.Logf("input ranges=%v", labelRanges(l))
	t.Logf("strings.ToValidUTF8 ranges=%v", labelRanges(sl))
	t.Logf("bytes.ToValidUTF8   ranges=%v", labelRanges(bl))
}
