// Woven-vs-plain differential program (review node hooks-fidelity-strings).
// Build once with `go build` and once with `go tool orchestrion go build`,
// run both, and diff stdout. Any difference is a behavior change introduced
// by weaving (evaluation order, panics, results, types).
package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

type named string
type namedB []byte

type holder struct{ s string }

var log []string

func trace(tag string, v int) int { log = append(log, tag); return v }

func try(name string, f func() any) {
	log = nil
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("%-28s PANIC %T: %v | order=%v\n", name, r, r, log)
		}
	}()
	v := f()
	fmt.Printf("%-28s %q | order=%v\n", name, fmt.Sprint(v), log)
}

func main() {
	var ctx context.Context = context.Background()
	if os.Getenv("ACTIVE") == "1" {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
		c, scope, _ := request.Begin(ctx)
		defer scope.Finish()
		ctx = c
	}
	src := func(v string) string {
		return taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "q"}, v)
	}
	srcB := func(v string) []byte {
		return taint.TaintBytes(ctx, taint.Source{Origin: taint.OriginHttpRequestBody, Name: "b"}, []byte(v))
	}

	// 1. Concat operand mutated by a later call operand.
	try("concat-mutate-local", func() any {
		s := src("orig")
		f := func() string { s = "CHANGED"; return "|f" }
		return s + f()
	})
	try("concat-mutate-local-3", func() any {
		s := src("orig")
		f := func() string { s = "CHANGED"; return "|f" }
		return s + f() + s
	})
	try("concat-mutate-field", func() any {
		h := &holder{s: src("field")}
		f := func() string { h.s = "CHANGED"; return "|f" }
		return h.s + f()
	})
	try("concat-mutate-map", func() any {
		m := map[string]string{"k": src("mapv")}
		f := func() string { m["k"] = "CHANGED"; return "|f" }
		return m["k"] + f()
	})
	try("concat-mutate-global", func() any {
		global = src("global")
		f := func() string { global = "CHANGED"; return "|f" }
		return global + f()
	})
	try("concat-order-calls", func() any {
		g := func(t string) string { log = append(log, t); return t }
		return g("a") + g("b") + g("c")
	})
	try("concat-panic-order", func() any {
		g := func(t string) string { log = append(log, t); return t }
		p := func() string { panic("p") }
		return g("a") + p() + g("c")
	})
	try("concat-named", func() any {
		var n named = named(src("nm"))
		r := n + "-" + n
		return fmt.Sprintf("%T:%v", r, r)
	})
	try("concat-untyped-mix", func() any {
		s := src("x")
		const c = "c1" + "c2"
		return "a" + s + ("b" + "c") + c
	})
	// 2. Slicing with a mutating bound.
	try("slice-low-mutate", func() any {
		s := src("abcdef")
		f := func() int { s = "XY"; return 1 }
		return s[f():]
	})
	try("slice-high-mutate", func() any {
		s := src("abcdef")
		f := func() int { s = "XYZW"; return 3 }
		return s[:f()]
	})
	try("slice-bounds-order", func() any {
		s := src("abcdef")
		return s[trace("lo", 1):trace("hi", 9)]
	})
	try("slice-bytes-mutate", func() any {
		b := srcB("abcdef")
		f := func() int { b = []byte("XYZW"); return 2 }
		return string(b[f():])
	})
	try("slice-bytes-full-order", func() any {
		b := srcB("abcdef")
		r := b[trace("lo", 1):trace("hi", 3):trace("max", 4)]
		return fmt.Sprint(string(r), len(r), cap(r))
	})
	try("slice-bytes-alias", func() any {
		b := srcB("abcdef")
		r := b[1:3]
		r[0] = 'Z'
		return string(b)
	})
	try("slice-field-mutate", func() any {
		h := &holder{s: src("abcdef")}
		f := func() int { h.s = "XY"; return 1 }
		return h.s[f():]
	})
	try("slice-oob", func() any { s := src("abc"); i := 5; return s[i:] })
	try("slice-oob-uint8", func() any { s := src("abc"); var i uint8 = 200; return s[:i] })
	try("slice-inverted", func() any { s := src("abc"); i, j := 2, 1; return s[i:j] })
	try("slice-named", func() any { n := named(src("abcdef")); r := n[1:3]; return fmt.Sprintf("%T:%v", r, r) })
	try("slice-rune-const", func() any { s := src(strings.Repeat("z", 100)); return len(s['a':]) })
	// 3. bytes->string conversion.
	try("conv-mutate-after", func() any {
		b := srcB("abcdef")
		s := string(b)
		b[0] = 'Z'
		return s
	})
	try("conv-named", func() any { b := namedB(srcB("abcd")); r := named(b); return fmt.Sprintf("%T:%v", r, r) })
	try("conv-nil", func() any { var b []byte; return string(b) == "" })
	// 4. Direct call replacement with mutating later args.
	try("split-mutate", func() any {
		s := src("a,b,c")
		f := func() string { s = "x;y"; return ";" }
		return strings.Split(s, f())
	})
	try("replace-order", func() any {
		g := func(t string) string { log = append(log, t); return t }
		return strings.Replace(g("aaa"), g("a"), g("b"), trace("n", 2))
	})
	try("repeat-neg", func() any { return strings.Repeat(src("ab"), -1) })
	try("repeat-overflow", func() any { return strings.Repeat(src("ab"), int(^uint(0)>>1)) })
	try("replacer-nil", func() any { var r *strings.Replacer; return r.Replace(src("abc")) })
	try("replacer-value", func() any { r := *strings.NewReplacer("a", "b"); return r.Replace(src("aaa")) })
	try("sprintf-stringer-count", func() any {
		n := 0
		c := counting{&n}
		s := fmt.Sprintf("%v %s", c, src("zz"))
		return fmt.Sprint(s, n)
	})
	try("sprint-panic-stringer", func() any { return fmt.Sprint(src("aa"), boom{}) })
	try("unescape-err", func() any { v, err := url.QueryUnescape(src("%zz")); return fmt.Sprint(v, err) })
	try("unquote-err", func() any { v, err := strconv.Unquote(src(`"x`)); return fmt.Sprint(v, err) })
	try("seq-break", func() any {
		var out []string
		for v := range strings.SplitSeq(src("a,b,c,d"), ",") {
			out = append(out, v)
			if len(out) == 2 {
				break
			}
		}
		return out
	})
	try("lines-panic-body", func() any {
		for v := range strings.Lines(src("a\nb\n")) {
			panic("body " + v)
		}
		return nil
	})
	try("fieldsfunc-count", func() any {
		n := 0
		r := strings.FieldsFunc(src("a b  c"), func(r rune) bool { n++; return r == ' ' })
		return fmt.Sprint(r, n)
	})
	try("tovalid", func() any { return strings.ToValidUTF8(src("a\xffb\xfe\xfd"), src("??")) })
	try("toupper-special", func() any { return strings.ToUpper(src("ß\xffİǆ")) })
}

var global string

type counting struct{ n *int }

func (c counting) String() string { *c.n++; return "C" }

type boom struct{}

func (boom) String() string { panic("boom") }
