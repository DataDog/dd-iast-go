// Review-only property test: every exported ranges operation against a naive
// per-byte label-array oracle. Not intended for merge as-is.

package ranges_test

import (
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"strconv"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

// label is the per-byte oracle state.
type label struct {
	set    bool
	source ranges.SourceID
	marks  uint64
}

type labels []label

func normLimit(l ranges.Limit) int {
	if l == 0 {
		return ranges.DefaultLimit
	}
	if l > ranges.HardLimit {
		return ranges.HardLimit
	}
	return int(l)
}

// runsOf is the naive canonical form: maximal runs of equal set labels.
func runsOf(ls labels) []ranges.Range {
	var out []ranges.Range
	for i := 0; i < len(ls); {
		if !ls[i].set {
			i++
			continue
		}
		j := i + 1
		for j < len(ls) && ls[j] == ls[i] {
			j++
		}
		out = append(out, ranges.Range{Start: uint32(i), Length: uint32(j - i), SourceID: ls[i].source, Marks: ls[i].marks})
		i = j
	}
	return out
}

func expectFromLabels(ls labels, limit int) ([]ranges.Range, bool) {
	r := runsOf(ls)
	if len(r) > limit {
		return r[:limit], true
	}
	return r, false
}

// labelsOf expands a set into per-byte labels, byte by byte.
func labelsOf(s *ranges.Set, n uint32) labels {
	ls := make(labels, n)
	if s == nil {
		return ls
	}
	for i := 0; i < s.Len(); i++ {
		r, _ := s.At(i)
		for p := r.Start; p < r.Start+r.Length; p++ {
			ls[p] = label{true, r.SourceID, r.Marks}
		}
	}
	return ls
}

func setRanges(s *ranges.Set) []ranges.Range {
	out := make([]ranges.Range, s.Len())
	s.CopyTo(out)
	return out
}

var markPool = []uint64{0, 1 << 1, 1 << 2, 1<<1 | 1<<2, 1 << 5, 1<<3 | 1<<7}

func randLabel(r *rand.Rand) label {
	return label{true, ranges.SourceID(r.IntN(4)), markPool[r.IntN(len(markPool))]}
}

// randLabels makes run-structured labels so adjacent-merge cases are frequent.
func randLabels(r *rand.Rand, n int) labels {
	ls := make(labels, n)
	var cur label
	for i := range ls {
		switch r.IntN(6) {
		case 0:
			cur = label{}
		case 1, 2:
			cur = randLabel(r)
		}
		ls[i] = cur
	}
	return ls
}

func randLimit(r *rand.Rand) ranges.Limit {
	switch r.IntN(10) {
	case 0:
		return 0 // normalizes to DefaultLimit
	case 1:
		return ranges.Limit(65 + r.IntN(190)) // normalizes to HardLimit
	case 2, 3:
		return ranges.Limit(r.IntN(3) + 1)
	default:
		return ranges.Limit(r.IntN(ranges.HardLimit) + 1)
	}
}

// randSet builds a valid input set with a random limit; its labels are derived
// back from the published set so input truncation is accounted for.
func randSet(t *testing.T, r *rand.Rand, n int) (*ranges.Set, labels) {
	t.Helper()
	if r.IntN(8) == 0 {
		return nil, make(labels, n)
	}
	runs := runsOf(randLabels(r, n))
	if len(runs) > ranges.HardLimit {
		runs = runs[:ranges.HardLimit]
	}
	s := new(ranges.Set)
	o := ranges.AdoptCanonical(s, randLimit(r), runs, uint32(n))
	if !o.Valid {
		t.Fatalf("setup AdoptCanonical failed")
	}
	tracked = append(tracked, trackedInput{s, setRanges(s), s.Limit()})
	return s, labelsOf(s, uint32(n))
}

type trackedInput struct {
	s     *ranges.Set
	snap  []ranges.Range
	limit ranges.Limit
}

// tracked records every input set of the current case so the harness can
// assert that operations never mutate a non-destination input.
var tracked []trackedInput

func checkInputsUnchanged(c checker, dst *ranges.Set) {
	c.t.Helper()
	for _, in := range tracked {
		if in.s == dst {
			continue
		}
		now := setRanges(in.s)
		if fmt.Sprint(now) != fmt.Sprint(in.snap) || in.s.Limit() != in.limit {
			c.fail("input-immutability", "input mutated: before %v/%d after %v/%d", in.snap, in.limit, now, in.s.Limit())
		}
	}
}

// byteSource feeds fuzzer bytes into math/rand so coverage-guided mutation
// steers every generator choice of runOracleCase.
// Once the bytes are exhausted it continues with a deterministic splitmix64
// stream (a constant stream would spin math/rand's rejection sampling).
type byteSource struct {
	data  []byte
	state uint64
}

func (b *byteSource) Uint64() uint64 {
	if len(b.data) == 0 {
		b.state += 0x9E3779B97F4A7C15
		z := b.state
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
		z = (z ^ (z >> 27)) * 0x94D049BB133111EB
		return z ^ (z >> 31)
	}
	var v uint64
	for i := 0; i < 8; i++ {
		v <<= 8
		if len(b.data) > 0 {
			v |= uint64(b.data[0])
			b.state = b.state*31 + uint64(b.data[0])
			b.data = b.data[1:]
		}
	}
	return v
}

func FuzzReviewOperationsOracle(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
	f.Add([]byte("\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\x80\x40\x20\x10\x08\x04\x02\x01"))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := rand.New(&byteSource{data: data})
		runOracleCase(t, r, checker{t, 0, 0})
	})
}

func garbage() *ranges.Set {
	g := new(ranges.Set)
	ranges.AdoptCanonical(g, 64, []ranges.Range{{Start: 0, Length: 3, SourceID: 9, Marks: 2}, {Start: 5, Length: 7, SourceID: 8}}, 100)
	return g
}

type checker struct {
	t    *testing.T
	seed uint64
	iter int
}

func (c checker) fail(op, format string, args ...any) {
	c.t.Helper()
	c.t.Fatalf("seed=%d iter=%d op=%s: %s", c.seed, c.iter, op, fmt.Sprintf(format, args...))
}

func (c checker) valid(op string, got *ranges.Set, o ranges.Outcome, ls labels, limit int) {
	c.t.Helper()
	want, trunc := expectFromLabels(ls, limit)
	if !o.Valid {
		c.fail(op, "rejected valid input; want %v", want)
	}
	have := setRanges(got)
	if len(have) != len(want) {
		c.fail(op, "count: want %v have %v", want, have)
	}
	for i := range want {
		if want[i] != have[i] {
			c.fail(op, "range %d: want %v have %v", i, want, have)
		}
	}
	if trunc != o.Truncated {
		c.fail(op, "truncated: want %v have %v (want=%v)", trunc, o.Truncated, want)
	}
	if !got.ValidFor(uint32(len(ls))) {
		c.fail(op, "result not ValidFor(%d): %v", len(ls), have)
	}
	if int(got.Limit()) != limit {
		c.fail(op, "limit: want %d have %d", limit, got.Limit())
	}
}

func (c checker) invalid(op string, got *ranges.Set, o ranges.Outcome, limit int) {
	c.t.Helper()
	if o.Valid || o.Truncated {
		c.fail(op, "accepted invalid input: %+v %v", o, setRanges(got))
	}
	if got.Len() != 0 {
		c.fail(op, "invalid result not reset: %v", setRanges(got))
	}
	if int(got.Limit()) != limit {
		c.fail(op, "invalid limit: want %d have %d", limit, got.Limit())
	}
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return def
}

func TestReviewOperationsAgainstPerByteOracle(t *testing.T) {
	seed := uint64(envInt("RANGES_ORACLE_SEED", 20260923))
	cases := envInt("RANGES_ORACLE_CASES", 100_000)
	r := rand.New(rand.NewPCG(seed, seed^0x9E3779B97F4A7C15))
	counts := map[string]int{}
	for iter := 0; iter < cases; iter++ {
		op := runOracleCase(t, r, checker{t, seed, iter})
		counts[strconv.Itoa(op)]++
	}
	t.Logf("seed=%d cases=%d per-op=%v", seed, cases, counts)
}

func runOracleCase(t *testing.T, r *rand.Rand, c checker) int {
	tracked = tracked[:0]
	{
		op := r.IntN(17)
		limit := randLimit(r)
		nl := normLimit(limit)
		n := r.IntN(96)
		dst := garbage()
		switch op {
		case 0: // Canonicalize
			valueLen := uint32(n)
			k := r.IntN(40)
			if r.IntN(20) == 0 {
				k = ranges.MaxCanonicalInput - r.IntN(3) + r.IntN(3) // around the bound
			}
			raw := make([]ranges.Range, 0, k)
			for i := 0; i < k && valueLen > 0; i++ {
				s := uint32(r.IntN(int(valueLen)))
				l := uint32(r.IntN(int(valueLen-s))) + 1
				raw = append(raw, ranges.Range{Start: s, Length: l, SourceID: ranges.SourceID(r.IntN(4)), Marks: markPool[r.IntN(len(markPool))]})
			}
			bad := false
			if len(raw) > 0 && r.IntN(10) == 0 {
				i := r.IntN(len(raw))
				switch r.IntN(5) {
				case 0:
					raw[i].Length = 0
				case 1:
					raw[i].Start = math.MaxUint32
					raw[i].Length = 2
				case 2:
					raw[i].Length = valueLen - raw[i].Start + 1
				case 3:
					raw[i].Marks |= 1
				case 4:
					raw[i].Marks |= 1 << 63
				}
				bad = true
			}
			if len(raw) > ranges.MaxCanonicalInput {
				bad = true
			}
			// Naive oracle: first writer wins per byte.
			ls := make(labels, valueLen)
			for _, x := range raw {
				for p := x.Start; p < x.Start+x.Length && p < valueLen && p >= x.Start; p++ {
					if !ls[p].set {
						ls[p] = label{true, x.SourceID, x.Marks}
					}
				}
			}
			o := ranges.Canonicalize(dst, limit, raw, valueLen)
			if bad {
				c.invalid("Canonicalize", dst, o, nl)
			} else {
				c.valid("Canonicalize", dst, o, ls, nl)
			}
		case 1: // AdoptCanonical, including non-canonical input
			ls := randLabels(r, n)
			runs := runsOf(ls)
			bad := false
			if len(runs) >= 2 && r.IntN(4) == 0 {
				switch r.IntN(3) {
				case 0: // overlap
					runs[1].Start = runs[0].Start
				case 1: // split a run into two mergeable pieces
					if runs[0].Length >= 2 {
						a := runs[0]
						a.Length = 1
						b := runs[0]
						b.Start++
						b.Length--
						runs = append([]ranges.Range{a, b}, runs[1:]...)
					} else {
						runs[1], runs[0] = runs[0], runs[1] // unsorted
					}
				case 2:
					runs[0], runs[1] = runs[1], runs[0]
				}
				bad = true
			}
			if len(runs) > ranges.HardLimit {
				bad = true
			}
			valueLen := uint32(n)
			if len(runs) > 0 && r.IntN(15) == 0 {
				valueLen = runs[len(runs)-1].Start + runs[len(runs)-1].Length - 1
				bad = true
			}
			o := ranges.AdoptCanonical(dst, limit, runs, valueLen)
			if bad {
				c.invalid("AdoptCanonical", dst, o, nl)
			} else {
				c.valid("AdoptCanonical", dst, o, ls, nl)
			}
		case 2: // Copy (also aliasing dst==source)
			src, ls := randSet(t, r, n)
			if src != nil && r.IntN(2) == 0 {
				dst = src
			}
			if src != nil && src.Len() > 0 && r.IntN(12) == 0 {
				last, _ := src.At(src.Len() - 1)
				o := ranges.Copy(dst, limit, src, last.Start+last.Length-1)
				c.invalid("Copy/short", dst, o, nl)
				break
			}
			o := ranges.Copy(dst, limit, src, uint32(n))
			c.valid("Copy", dst, o, ls, nl)
		case 3: // Shift
			src, ls := randSet(t, r, n)
			offset := uint32(r.IntN(40))
			resultLen := uint32(n) + offset + uint32(r.IntN(20))
			if r.IntN(10) == 0 && resultLen > 0 {
				resultLen = uint32(n) + offset - 1
				if uint32(n)+offset == 0 {
					resultLen = 0
				}
				if uint32(n)+offset > 0 {
					o := ranges.Shift(dst, limit, src, uint32(n), offset, resultLen)
					c.invalid("Shift/short", dst, o, nl)
					break
				}
			}
			want := make(labels, resultLen)
			copy(want[offset:], ls)
			if src != nil && r.IntN(2) == 0 {
				dst = src
			}
			o := ranges.Shift(dst, limit, src, uint32(n), offset, resultLen)
			c.valid("Shift", dst, o, want, nl)
		case 4, 5: // Concat / Append
			a, la := randSet(t, r, n)
			m := r.IntN(96)
			b, lb := randSet(t, r, m)
			want := append(append(labels{}, la...), lb...)
			if a != nil && r.IntN(3) == 0 {
				dst = a
			} else if b != nil && r.IntN(3) == 0 {
				dst = b
			}
			var o ranges.Outcome
			if op == 4 {
				o = ranges.Concat(dst, limit, a, uint32(n), b, uint32(m))
			} else {
				o = ranges.Append(dst, limit, a, uint32(n), b, uint32(m))
			}
			c.valid("Concat/Append", dst, o, want, nl)
		case 6: // Slice
			src, ls := randSet(t, r, n)
			lo, hi := uint32(r.IntN(n+1)), uint32(r.IntN(n+1))
			if r.IntN(12) == 0 {
				if lo == hi {
					hi = uint32(n) + 1
				} else if lo < hi {
					lo, hi = hi, lo
				}
				o := ranges.Slice(dst, limit, src, uint32(n), lo, hi)
				c.invalid("Slice/bad", dst, o, nl)
				break
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			if src != nil && r.IntN(2) == 0 {
				dst = src
			}
			o := ranges.Slice(dst, limit, src, uint32(n), lo, hi)
			c.valid("Slice", dst, o, append(labels{}, ls[lo:hi]...), nl)
		case 7: // Join with 0..6 elements
			sepLen := r.IntN(5)
			sep, lsep := randSet(t, r, sepLen)
			k := r.IntN(7)
			parts := make([]ranges.Part, k)
			var want labels
			for i := range parts {
				el := r.IntN(30)
				s, ls := randSet(t, r, el)
				parts[i] = ranges.Part{Ranges: s, Length: uint32(el)}
				want = append(want, ls...)
				if i+1 < k {
					want = append(want, lsep...)
				}
			}
			o := ranges.Join(dst, limit, parts, ranges.Part{Ranges: sep, Length: uint32(sepLen)})
			c.valid("Join", dst, o, want, nl)
		case 8: // Repeat
			src, ls := randSet(t, r, n%40)
			count := r.IntN(9)
			if r.IntN(15) == 0 {
				o := ranges.Repeat(dst, limit, src, uint32(n%40), -1-r.IntN(5))
				c.invalid("Repeat/neg", dst, o, nl)
				break
			}
			var want labels
			for range count {
				want = append(want, ls...)
			}
			if src != nil && r.IntN(2) == 0 {
				dst = src
			}
			o := ranges.Repeat(dst, limit, src, uint32(n%40), count)
			c.valid("Repeat", dst, o, want, nl)
		case 9: // Compose with 0..6 segments, including the same set twice
			k := r.IntN(7)
			segs := make([]ranges.Segment, k)
			var want labels
			var prev *ranges.Set
			var prevLs labels
			var prevLen int
			for i := range segs {
				el := r.IntN(40)
				s, ls := randSet(t, r, el)
				if prev != nil && r.IntN(4) == 0 {
					s, ls, el = prev, prevLs, prevLen
				}
				lo, hi := r.IntN(el+1), r.IntN(el+1)
				if lo > hi {
					lo, hi = hi, lo
				}
				segs[i] = ranges.Segment{Part: ranges.Part{Ranges: s, Length: uint32(el)}, Low: uint32(lo), High: uint32(hi)}
				want = append(want, ls[lo:hi]...)
				prev, prevLs, prevLen = s, ls, el
			}
			if k > 0 && r.IntN(15) == 0 {
				j := r.IntN(k)
				segs[j].High = segs[j].Length + 1
				o := ranges.Compose(dst, limit, segs)
				c.invalid("Compose/bad", dst, o, nl)
				break
			}
			o := ranges.Compose(dst, limit, segs)
			c.valid("Compose", dst, o, want, nl)
		case 10: // Clear
			src, ls := randSet(t, r, n)
			lo, hi := r.IntN(n+1), r.IntN(n+1)
			if lo > hi {
				lo, hi = hi, lo
			}
			want := append(labels{}, ls...)
			clear(want[lo:hi])
			if src != nil && r.IntN(2) == 0 {
				dst = src
			}
			o := ranges.Clear(dst, limit, src, uint32(n), uint32(lo), uint32(hi))
			c.valid("Clear", dst, o, want, nl)
		case 11, 12: // Overwrite / Write / CopyOverwrite, incl. base==source
			base, lb := randSet(t, r, n)
			m := r.IntN(96)
			src, ls := randSet(t, r, m)
			if r.IntN(3) == 0 {
				src, ls, m = base, lb, n
			}
			nn := r.IntN(min(n, m) + 1)
			d := r.IntN(n - nn + 1)
			so := r.IntN(m - nn + 1)
			if op == 12 {
				so = 0
			}
			if r.IntN(15) == 0 {
				o := ranges.Overwrite(dst, limit, base, uint32(n), uint32(d), src, uint32(m), uint32(m-nn+1), uint32(nn))
				c.invalid("Overwrite/bad", dst, o, nl)
				break
			}
			want := append(labels{}, lb...)
			copy(want[d:d+nn], ls[so:so+nn])
			if base != nil && r.IntN(2) == 0 {
				dst = base
			}
			var o ranges.Outcome
			switch {
			case op == 12:
				o = ranges.Write(dst, limit, base, uint32(n), uint32(d), src, uint32(m), uint32(nn))
			case r.IntN(2) == 0:
				o = ranges.CopyOverwrite(dst, limit, base, uint32(n), uint32(d), src, uint32(m), uint32(so), uint32(nn))
			default:
				o = ranges.Overwrite(dst, limit, base, uint32(n), uint32(d), src, uint32(m), uint32(so), uint32(nn))
			}
			c.valid("Overwrite", dst, o, want, nl)
		case 13: // Coarse
			k := r.IntN(5)
			parts := make([]ranges.Part, k)
			var found bool
			var src ranges.SourceID
			var marks uint64
			for i := range parts {
				el := r.IntN(30)
				s, ls := randSet(t, r, el)
				parts[i] = ranges.Part{Ranges: s, Length: uint32(el)}
				for _, x := range ls { // per-byte, input order
					if !x.set {
						continue
					}
					if !found {
						found, src, marks = true, x.source, x.marks
					} else {
						marks &= x.marks
					}
				}
			}
			outLen := r.IntN(60)
			want := make(labels, outLen)
			if found {
				for i := range want {
					want[i] = label{true, src, marks}
				}
			}
			o := ranges.Coarse(dst, limit, uint32(outLen), parts)
			c.valid("Coarse", dst, o, want, nl)
		case 14, 15, 16: // MarkAll / MarkSource / UnsafeFor
			s, ls := randSet(t, r, n)
			if s == nil {
				s = new(ranges.Set)
			}
			vuln := constants.VulnerabilityType(r.IntN(int(constants.VulnerabilityTypeCount)) + 1)
			badVuln := r.IntN(15) == 0
			if badVuln {
				if r.IntN(2) == 0 {
					vuln = 0
				} else {
					vuln = constants.VulnerabilityType(constants.VulnerabilityTypeCount + 1 + uint(r.IntN(100)))
				}
			}
			srcLimit := int(s.Limit())
			id := ranges.SourceID(r.IntN(4))
			if r.IntN(2) == 0 {
				dst = s
			}
			var o ranges.Outcome
			bit := uint64(1) << uint(vuln%64)
			want := append(labels{}, ls...)
			switch op {
			case 14:
				o = ranges.MarkAll(dst, s, vuln)
				for i := range want {
					if want[i].set {
						want[i].marks |= bit
					}
				}
			case 15:
				o = ranges.MarkSource(dst, s, id, vuln)
				for i := range want {
					if want[i].set && want[i].source == id {
						want[i].marks |= bit
					}
				}
			case 16:
				o = ranges.UnsafeFor(dst, s, vuln)
				for i := range want {
					if want[i].set && want[i].marks&bit != 0 {
						want[i] = label{}
					}
				}
			}
			if badVuln {
				c.invalid("Mark/badvuln", dst, o, srcLimit)
			} else {
				c.valid(fmt.Sprintf("Mark/%d", op), dst, o, want, srcLimit)
			}
		}
		checkInputsUnchanged(c, dst)
		return op
	}
}

// Repeat with a huge count and a multi-range source must stop after the limit
// is reached (bounded work) and publish the oracle prefix.
func TestReviewRepeatHugeCountBoundedAndExact(t *testing.T) {
	src := new(ranges.Set)
	raw := []ranges.Range{{Start: 0, Length: 1, SourceID: 1}, {Start: 2, Length: 1, SourceID: 2}}
	if !ranges.AdoptCanonical(src, 64, raw, 3).Valid {
		t.Fatal("setup")
	}
	for _, limit := range []ranges.Limit{1, 10, 64} {
		var d ranges.Set
		count := int(math.MaxUint32 / 3)
		o := ranges.Repeat(&d, limit, src, 3, count)
		one := labelsOf(src, 3)
		var want labels
		for range int(limit) + 2 {
			want = append(want, one...)
		}
		exp, _ := expectFromLabels(want, int(limit))
		if !o.Valid || !o.Truncated || fmt.Sprint(setRanges(&d)) != fmt.Sprint(exp) {
			t.Fatalf("limit=%d outcome=%+v have=%v want=%v", limit, o, setRanges(&d), exp)
		}
	}
}

// Boundary cases that a byte-array oracle cannot represent: offsets and
// lengths near the uint32 limit must be rejected or computed without wrap.
func TestReviewUint32Boundaries(t *testing.T) {
	const maxU = math.MaxUint32
	one := func(start, length uint32) *ranges.Set {
		s := new(ranges.Set)
		if !ranges.AdoptCanonical(s, 64, []ranges.Range{{Start: start, Length: length, SourceID: 1}}, start+length).Valid {
			t.Fatalf("setup %d+%d", start, length)
		}
		return s
	}
	var d ranges.Set
	// Shift to the very end is valid; one more byte wraps and must be invalid.
	if o := ranges.Shift(&d, 10, one(0, 1), 1, maxU-1, maxU); !o.Valid || d.Len() != 1 {
		t.Fatalf("shift to end: %+v %v", o, setRanges(&d))
	}
	if o := ranges.Shift(&d, 10, one(0, 1), 1, maxU, maxU); o.Valid || d.Len() != 0 {
		t.Fatalf("shift wrap accepted: %+v %v", o, setRanges(&d))
	}
	// Concat total overflow.
	if o := ranges.Concat(&d, 10, one(0, 1), maxU, one(0, 1), 1); o.Valid {
		t.Fatalf("concat wrap accepted: %v", setRanges(&d))
	}
	// Concat exactly at the limit.
	if o := ranges.Concat(&d, 10, one(maxU-2, 1), maxU-1, one(0, 1), 1); !o.Valid || d.Len() != 1 {
		t.Fatalf("concat at limit: %+v %v", o, setRanges(&d))
	} else if r, _ := d.At(0); r.Start != maxU-2 || r.Length != 2 {
		t.Fatalf("concat at limit merged wrongly: %v", setRanges(&d))
	}
	// Join total overflow (element + separator).
	if o := ranges.Join(&d, 10, []ranges.Part{{Length: maxU}, {Length: 0}}, ranges.Part{Length: 1}); o.Valid {
		t.Fatalf("join wrap accepted")
	}
	// Repeat overflow and exact fit.
	if o := ranges.Repeat(&d, 10, one(0, 2), 2, 1<<31); o.Valid {
		t.Fatalf("repeat wrap accepted: %v", setRanges(&d))
	}
	if o := ranges.Repeat(&d, 10, one(0, 1), 1, maxU); !o.Valid || d.Len() != 1 {
		t.Fatalf("repeat exact fit: %+v", o)
	} else if r, _ := d.At(0); r.Length != maxU {
		t.Fatalf("repeat length: %v", r)
	}
	// Compose total overflow.
	big := ranges.Segment{Part: ranges.Part{Length: maxU}, Low: 0, High: maxU}
	small := ranges.Segment{Part: ranges.Part{Ranges: one(0, 1), Length: 1}, Low: 0, High: 1}
	if o := ranges.Compose(&d, 10, []ranges.Segment{big, small}); o.Valid {
		t.Fatalf("compose wrap accepted: %v", setRanges(&d))
	}
	// Overwrite offset overflow.
	if o := ranges.Overwrite(&d, 10, nil, maxU, maxU, one(0, 1), 1, 0, 1); o.Valid {
		t.Fatalf("overwrite wrap accepted")
	}
	// Canonicalize: range ending exactly at MaxUint32 and a wrapping one.
	if o := ranges.Canonicalize(&d, 10, []ranges.Range{{Start: maxU - 1, Length: 1}}, maxU); !o.Valid || d.Len() != 1 {
		t.Fatalf("canonicalize at end: %+v", o)
	}
	if o := ranges.Canonicalize(&d, 10, []ranges.Range{{Start: maxU, Length: 1}}, maxU); o.Valid {
		t.Fatalf("canonicalize wrap accepted")
	}
	// Coarse with zero output length publishes nothing but is valid.
	if o := ranges.Coarse(&d, 10, 0, []ranges.Part{{Ranges: one(0, 1), Length: 1}}); !o.Valid || d.Len() != 0 {
		t.Fatalf("coarse zero output: %+v %v", o, setRanges(&d))
	}
	// Nil dst never panics.
	for _, f := range []func() ranges.Outcome{
		func() ranges.Outcome { return ranges.Canonicalize(nil, 1, nil, 0) },
		func() ranges.Outcome { return ranges.Copy(nil, 1, nil, 0) },
		func() ranges.Outcome { return ranges.Coarse(nil, 1, 1, nil) },
		func() ranges.Outcome { return ranges.MarkAll(nil, nil, 1) },
		func() ranges.Outcome { return ranges.UnsafeFor(nil, nil, 1) },
	} {
		if f().Valid {
			t.Fatalf("nil dst accepted")
		}
	}
}

// Worst-case Canonicalize fragmentation at MaxCanonicalInput must be accepted
// (the 2n-1 fragment bound) and match the oracle.
func TestReviewCanonicalizeWorstCaseFragmentation(t *testing.T) {
	n := ranges.MaxCanonicalInput
	valueLen := uint32(4 * n)
	raw := make([]ranges.Range, 0, n)
	// Nested intervals, innermost first: each outer range is split into two
	// fragments by all previously accepted inner ranges.
	for i := 0; i < n; i++ {
		c := valueLen / 2
		raw = append(raw, ranges.Range{Start: c - uint32(i) - 1, Length: 2*uint32(i) + 2, SourceID: ranges.SourceID(i % 2), Marks: 0})
	}
	ls := make(labels, valueLen)
	for _, x := range raw {
		for p := x.Start; p < x.Start+x.Length; p++ {
			if !ls[p].set {
				ls[p] = label{true, x.SourceID, x.Marks}
			}
		}
	}
	var d ranges.Set
	o := ranges.Canonicalize(&d, 64, raw, valueLen)
	checker{t, 0, 0}.valid("Canonicalize/worst", &d, o, ls, 64)

	// Interleaved: sorted disjoint singles then one covering range: 2n-1 pieces.
	raw = raw[:0]
	for i := 0; i < n-1; i++ {
		raw = append(raw, ranges.Range{Start: uint32(2*i + 1), Length: 1, SourceID: 1})
	}
	raw = append(raw, ranges.Range{Start: 0, Length: uint32(2*n - 1), SourceID: 2})
	ls = make(labels, valueLen)
	for _, x := range raw {
		for p := x.Start; p < x.Start+x.Length; p++ {
			if !ls[p].set {
				ls[p] = label{true, x.SourceID, x.Marks}
			}
		}
	}
	o = ranges.Canonicalize(&d, 64, raw, valueLen)
	checker{t, 0, 1}.valid("Canonicalize/interleaved", &d, o, ls, 64)
}
