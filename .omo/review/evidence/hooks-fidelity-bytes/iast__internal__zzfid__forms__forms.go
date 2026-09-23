// Package forms holds woven call-site forms for the hooks-fidelity-bytes review.
// Every function performs direct (hooked) calls; the test compares them with a
// reference built from method values / function values that are not hooked.
package forms

import (
	"bytes"
	"strings"
	"sync"
	"unicode"
)

// Log records evaluation order of receiver and argument expressions.
var Log []string

func mark(s string) { Log = append(Log, s) }

type Holder struct {
	B   bytes.Buffer
	PB  *bytes.Buffer
	SB  strings.Builder
	PSB *strings.Builder
}

type Embed struct{ bytes.Buffer }
type PEmbed struct{ *strings.Builder }

type AliasBuf = bytes.Buffer
type AliasBuilder = strings.Builder

type NamedBytes []byte

func getBuf(b *bytes.Buffer) *bytes.Buffer { mark("recv"); return b }
func arg(s string) string                  { mark("arg"); return s }
func idx(i int) int                        { mark("idx"); return i }

// BuilderForms exercises every hooked Builder method in many syntactic forms.
func BuilderForms(in string, inb []byte) (string, int, int) {
	var b strings.Builder
	b.WriteString(in)
	b.Write(inb)
	b.WriteByte('!')
	b.WriteRune('é')
	b.Grow(10)
	p := &b
	p.WriteString("|")
	(*p).WriteString(in)
	(&b).WriteString("|")
	h := &Holder{PSB: new(strings.Builder)}
	h.SB.WriteString(in)
	h.PSB.WriteString(in)
	b.WriteString(h.SB.String())
	b.WriteString(h.PSB.String())
	pe := PEmbed{&strings.Builder{}}
	pe.WriteString(in) // promoted
	pe.Builder.WriteString("+")
	b.WriteString(pe.String())
	var al AliasBuilder
	al.WriteString(in)
	b.WriteString(al.String())
	arr := [2]strings.Builder{}
	arr[idx(1)].WriteString(arg(in))
	b.WriteString(arr[1].String())
	b.WriteString(b.String()) // nested
	if n, err := b.WriteString("x"); err != nil || n != 1 {
		panic("bad")
	}
	f := b.WriteString // method value, unhooked
	f("~")
	func() {
		defer b.WriteString("[deferred]")
		defer b.WriteByte('#')
	}()
	var wg sync.WaitGroup
	wg.Add(1)
	var gb strings.Builder
	go func() { defer wg.Done(); gb.WriteString(in) }()
	wg.Wait()
	b.WriteString(gb.String())
	s := b.String()
	l, c := b.Len(), b.Cap()
	b.Reset()
	defer b.Reset()
	return s, l, c
}

// BufferForms exercises every hooked Buffer method in many syntactic forms.
func BufferForms(in string, inb []byte) (string, []string) {
	var b bytes.Buffer
	b.WriteString(in)
	b.Write(inb)
	b.WriteByte('!')
	b.WriteRune('é')
	b.Grow(10)
	b.Truncate(b.Len() - 1)
	getBuf(&b).WriteString(arg("|"))
	h := &Holder{PB: new(bytes.Buffer)}
	h.B.WriteString(in)
	h.PB.Write(inb)
	b.WriteString(h.B.String())
	b.WriteString(h.PB.String())
	var e Embed
	e.WriteString(in) // promoted
	e.Buffer.WriteString("+")
	b.WriteString(e.String())
	var al AliasBuf
	al.WriteString(in)
	b.WriteString(al.String())
	m := map[string]*bytes.Buffer{"k": new(bytes.Buffer)}
	m["k"].WriteString(in)
	b.Write(m["k"].Bytes())
	b.Write(b.Bytes()) // self alias
	var nb NamedBytes = []byte(in)
	b.Write(nb)
	func() {
		defer b.Truncate(3)
		defer b.WriteString("[deferred]")
	}()
	b.WriteString("tail")
	r, _, _ := b.ReadRune()
	s := b.String()
	unread := b.UnreadRune()
	st := []string{string(r), errString(unread)}
	var z *bytes.Buffer
	st = append(st, z.String())
	var gb bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); gb.Write(inb) }()
	wg.Wait()
	st = append(st, gb.String())
	defer b.Reset()
	return s, st
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

func two(v []byte) ([]byte, []byte) { return v, []byte("=") }

// BytesForms exercises byte function-call forms that stress replace-function.
func BytesForms(v []byte) []string {
	var out []string
	add := func(b ...[]byte) {
		for _, x := range b {
			out = append(out, string(x))
		}
	}
	before, after, found := bytes.Cut(two(v)) // multi-value argument
	add(before, after)
	out = append(out, map[bool]string{true: "T", false: "F"}[found])
	nb := NamedBytes(v)
	add(bytes.TrimSpace(nb), bytes.Clone(nb))
	add(bytes.Split(nb, []byte("="))...)
	add(bytes.Map(unicode.ToUpper, v), bytes.TrimFunc(v, unicode.IsSpace))
	add(bytes.Join([][]byte{v, v}, []byte(",")))
	defer bytes.Clone(v) // hooked call in defer
	return out
}
