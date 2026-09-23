// Package crashdiff is a review-only differential harness. Woven builds
// replace the direct stdlib calls in Woven; Native and Reflect use function
// values and reflection, which Orchestrion does not weave.
package crashdiff

import (
	"fmt"
	"iter"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"unsafe"
)

// Impl is the set of operations exercised by the differential fuzzer.
type Impl struct {
	Clone         func(string) string
	Cut           func(string, string) (string, string, bool)
	CutPrefix     func(string, string) (string, bool)
	CutSuffix     func(string, string) (string, bool)
	Split         func(string, string) []string
	SplitN        func(string, string, int) []string
	SplitAfter    func(string, string) []string
	SplitAfterN   func(string, string, int) []string
	SplitSeq      func(string, string) iter.Seq[string]
	SplitAfterSeq func(string, string) iter.Seq[string]
	Lines         func(string) iter.Seq[string]
	Fields        func(string) []string
	FieldsFunc    func(string, func(rune) bool) []string
	FieldsSeq     func(string) iter.Seq[string]
	FieldsFuncSeq func(string, func(rune) bool) iter.Seq[string]
	Join          func([]string, string) string
	Repeat        func(string, int) string
	Replace       func(string, string, string, int) string
	ReplaceAll    func(string, string, string) string
	ReplacerRepl  func(*strings.Replacer, string) string
	Trim          func(string, string) string
	TrimSpace     func(string) string
	TrimLeft      func(string, string) string
	TrimRight     func(string, string) string
	TrimPrefix    func(string, string) string
	TrimSuffix    func(string, string) string
	TrimFunc      func(string, func(rune) bool) string
	TrimLeftFunc  func(string, func(rune) bool) string
	TrimRightFunc func(string, func(rune) bool) string
	ToLower       func(string) string
	ToUpper       func(string) string
	ToTitle       func(string) string
	Map           func(func(rune) rune, string) string
	ToValidUTF8   func(string, string) string

	Sprint   func(...any) string
	Sprintf  func(string, ...any) string
	Sprintln func(...any) string

	QueryEscape   func(string) string
	PathEscape    func(string) string
	QueryUnescape func(string) (string, error)
	PathUnescape  func(string) (string, error)

	Quote          func(string) string
	QuoteToASCII   func(string) string
	QuoteToGraphic func(string) string
	Unquote        func(string) (string, error)

	BWrite       func(*strings.Builder, []byte) (int, error)
	BWriteString func(*strings.Builder, string) (int, error)
	BWriteByte   func(*strings.Builder, byte) error
	BWriteRune   func(*strings.Builder, rune) (int, error)
	BGrow        func(*strings.Builder, int)
	BReset       func(*strings.Builder)
	BString      func(*strings.Builder) string
	BCopyWrite   func(*strings.Builder, string) (int, error)

	Concat2   func(string, string) string
	Concat3   func(string, string, string) string
	Concat16  func([16]string) string
	Concat17  func([17]string) string
	Slice     func(string, int, int) string
	SliceLow  func(string, int) string
	SliceHigh func(string, int) string
	B2S       func([]byte) string
	B2SSlice  func([]byte, int, int) string
}

// Woven contains direct calls and operators that Orchestrion rewrites.
var Woven = Impl{
	Clone:         func(v string) string { return strings.Clone(v) },
	Cut:           func(v, s string) (string, string, bool) { return strings.Cut(v, s) },
	CutPrefix:     func(v, p string) (string, bool) { return strings.CutPrefix(v, p) },
	CutSuffix:     func(v, p string) (string, bool) { return strings.CutSuffix(v, p) },
	Split:         func(v, s string) []string { return strings.Split(v, s) },
	SplitN:        func(v, s string, n int) []string { return strings.SplitN(v, s, n) },
	SplitAfter:    func(v, s string) []string { return strings.SplitAfter(v, s) },
	SplitAfterN:   func(v, s string, n int) []string { return strings.SplitAfterN(v, s, n) },
	SplitSeq:      func(v, s string) iter.Seq[string] { return strings.SplitSeq(v, s) },
	SplitAfterSeq: func(v, s string) iter.Seq[string] { return strings.SplitAfterSeq(v, s) },
	Lines:         func(v string) iter.Seq[string] { return strings.Lines(v) },
	Fields:        func(v string) []string { return strings.Fields(v) },
	FieldsFunc:    func(v string, f func(rune) bool) []string { return strings.FieldsFunc(v, f) },
	FieldsSeq:     func(v string) iter.Seq[string] { return strings.FieldsSeq(v) },
	FieldsFuncSeq: func(v string, f func(rune) bool) iter.Seq[string] { return strings.FieldsFuncSeq(v, f) },
	Join:          func(e []string, s string) string { return strings.Join(e, s) },
	Repeat:        func(v string, n int) string { return strings.Repeat(v, n) },
	Replace:       func(v, o, r string, n int) string { return strings.Replace(v, o, r, n) },
	ReplaceAll:    func(v, o, r string) string { return strings.ReplaceAll(v, o, r) },
	ReplacerRepl:  func(r *strings.Replacer, v string) string { return r.Replace(v) },
	Trim:          func(v, c string) string { return strings.Trim(v, c) },
	TrimSpace:     func(v string) string { return strings.TrimSpace(v) },
	TrimLeft:      func(v, c string) string { return strings.TrimLeft(v, c) },
	TrimRight:     func(v, c string) string { return strings.TrimRight(v, c) },
	TrimPrefix:    func(v, c string) string { return strings.TrimPrefix(v, c) },
	TrimSuffix:    func(v, c string) string { return strings.TrimSuffix(v, c) },
	TrimFunc:      func(v string, f func(rune) bool) string { return strings.TrimFunc(v, f) },
	TrimLeftFunc:  func(v string, f func(rune) bool) string { return strings.TrimLeftFunc(v, f) },
	TrimRightFunc: func(v string, f func(rune) bool) string { return strings.TrimRightFunc(v, f) },
	ToLower:       func(v string) string { return strings.ToLower(v) },
	ToUpper:       func(v string) string { return strings.ToUpper(v) },
	ToTitle:       func(v string) string { return strings.ToTitle(v) },
	Map:           func(m func(rune) rune, v string) string { return strings.Map(m, v) },
	ToValidUTF8:   func(v, r string) string { return strings.ToValidUTF8(v, r) },

	Sprint:   func(a ...any) string { return fmt.Sprint(a...) },
	Sprintf:  func(f string, a ...any) string { return fmt.Sprintf(f, a...) },
	Sprintln: func(a ...any) string { return fmt.Sprintln(a...) },

	QueryEscape:   func(v string) string { return url.QueryEscape(v) },
	PathEscape:    func(v string) string { return url.PathEscape(v) },
	QueryUnescape: func(v string) (string, error) { return url.QueryUnescape(v) },
	PathUnescape:  func(v string) (string, error) { return url.PathUnescape(v) },

	Quote:          func(v string) string { return strconv.Quote(v) },
	QuoteToASCII:   func(v string) string { return strconv.QuoteToASCII(v) },
	QuoteToGraphic: func(v string) string { return strconv.QuoteToGraphic(v) },
	Unquote:        func(v string) (string, error) { return strconv.Unquote(v) },

	BWrite:       func(b *strings.Builder, p []byte) (int, error) { return b.Write(p) },
	BWriteString: func(b *strings.Builder, s string) (int, error) { return b.WriteString(s) },
	BWriteByte:   func(b *strings.Builder, c byte) error { return b.WriteByte(c) },
	BWriteRune:   func(b *strings.Builder, r rune) (int, error) { return b.WriteRune(r) },
	BGrow:        func(b *strings.Builder, n int) { b.Grow(n) },
	BReset:       func(b *strings.Builder) { b.Reset() },
	BString:      func(b *strings.Builder) string { return b.String() },
	BCopyWrite: func(b *strings.Builder, s string) (int, error) {
		c := *b
		return c.WriteString(s)
	},

	Concat2: func(a, b string) string { return a + b },
	Concat3: func(a, b, c string) string { return a + b + c },
	Concat16: func(v [16]string) string {
		return v[0] + v[1] + v[2] + v[3] + v[4] + v[5] + v[6] + v[7] + v[8] + v[9] + v[10] + v[11] + v[12] + v[13] + v[14] + v[15]
	},
	Concat17: func(v [17]string) string {
		return v[0] + v[1] + v[2] + v[3] + v[4] + v[5] + v[6] + v[7] + v[8] + v[9] + v[10] + v[11] + v[12] + v[13] + v[14] + v[15] + v[16]
	},
	Slice:     func(v string, i, j int) string { return v[i:j] },
	SliceLow:  func(v string, i int) string { return v[i:] },
	SliceHigh: func(v string, j int) string { return v[:j] },
	B2S:       func(b []byte) string { return string(b) },
	B2SSlice: func(b []byte, i, j int) string {
		s := string(b[i:j])
		return s
	},
}

func nativeJoin(parts []string) string {
	join := strings.Join
	return join(parts, "")
}

// nativeWindow builds v[i:j] without a slice expression. It reproduces the
// runtime bounds panic class (not the exact message) for invalid bounds.
func nativeWindow(v string, i, j int) string {
	if i < 0 || j < i || j > len(v) {
		panic("slice bounds out of range")
	}
	if i == j {
		return ""
	}
	return unsafe.String((*byte)(unsafe.Add(unsafe.Pointer(unsafe.StringData(v)), i)), j-i)
}

func nativeBytesString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	clone := strings.Clone
	return clone(unsafe.String(unsafe.SliceData(b), len(b)))
}

// Native contains function values and method expressions (not woven).
var Native = Impl{
	Clone: strings.Clone, Cut: strings.Cut, CutPrefix: strings.CutPrefix, CutSuffix: strings.CutSuffix,
	Split: strings.Split, SplitN: strings.SplitN, SplitAfter: strings.SplitAfter, SplitAfterN: strings.SplitAfterN,
	SplitSeq: strings.SplitSeq, SplitAfterSeq: strings.SplitAfterSeq, Lines: strings.Lines,
	Fields: strings.Fields, FieldsFunc: strings.FieldsFunc, FieldsSeq: strings.FieldsSeq, FieldsFuncSeq: strings.FieldsFuncSeq,
	Join: strings.Join, Repeat: strings.Repeat, Replace: strings.Replace, ReplaceAll: strings.ReplaceAll,
	ReplacerRepl: (*strings.Replacer).Replace,
	Trim:         strings.Trim, TrimSpace: strings.TrimSpace, TrimLeft: strings.TrimLeft, TrimRight: strings.TrimRight,
	TrimPrefix: strings.TrimPrefix, TrimSuffix: strings.TrimSuffix, TrimFunc: strings.TrimFunc,
	TrimLeftFunc: strings.TrimLeftFunc, TrimRightFunc: strings.TrimRightFunc,
	ToLower: strings.ToLower, ToUpper: strings.ToUpper, ToTitle: strings.ToTitle, Map: strings.Map, ToValidUTF8: strings.ToValidUTF8,
	Sprint: fmt.Sprint, Sprintf: fmt.Sprintf, Sprintln: fmt.Sprintln,
	QueryEscape: url.QueryEscape, PathEscape: url.PathEscape, QueryUnescape: url.QueryUnescape, PathUnescape: url.PathUnescape,
	Quote: strconv.Quote, QuoteToASCII: strconv.QuoteToASCII, QuoteToGraphic: strconv.QuoteToGraphic, Unquote: strconv.Unquote,

	BWrite: (*strings.Builder).Write, BWriteString: (*strings.Builder).WriteString, BWriteByte: (*strings.Builder).WriteByte,
	BWriteRune: (*strings.Builder).WriteRune, BGrow: (*strings.Builder).Grow, BReset: (*strings.Builder).Reset,
	BString: (*strings.Builder).String,
	BCopyWrite: func(b *strings.Builder, s string) (int, error) {
		c := *b
		write := (*strings.Builder).WriteString
		return write(&c, s)
	},

	Concat2:   func(a, b string) string { return nativeJoin([]string{a, b}) },
	Concat3:   func(a, b, c string) string { return nativeJoin([]string{a, b, c}) },
	Concat16:  func(v [16]string) string { return nativeJoin(v[:]) },
	Concat17:  func(v [17]string) string { return nativeJoin(v[:]) },
	Slice:     nativeWindow,
	SliceLow:  func(v string, i int) string { return nativeWindow(v, i, len(v)) },
	SliceHigh: func(v string, j int) string { return nativeWindow(v, 0, j) },
	B2S:       nativeBytesString,
	B2SSlice: func(b []byte, i, j int) string {
		if i < 0 || j < i || j > cap(b) {
			panic("slice bounds out of range")
		}
		if i == j {
			return ""
		}
		return nativeBytesString(unsafe.Slice((*byte)(unsafe.Add(unsafe.Pointer(unsafe.SliceData(b)), i)), j-i))
	},
}

// Reflect invokes every Native function through reflect.Value.Call.
var Reflect = func() Impl {
	var out Impl
	src := reflect.ValueOf(Native)
	dst := reflect.ValueOf(&out).Elem()
	for i := 0; i < src.NumField(); i++ {
		fn := src.Field(i)
		typ := fn.Type()
		dst.Field(i).Set(reflect.MakeFunc(typ, func(args []reflect.Value) []reflect.Value {
			if typ.IsVariadic() {
				return fn.CallSlice(args)
			}
			return fn.Call(args)
		}))
	}
	return out
}()
