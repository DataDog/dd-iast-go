// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command hooked imports nothing from dd-iast-go. It uses all the hooked
// paths of package stream in the standard library packages fmt, io, bufio and
// encoding/json, so that the linker keeps the hooks and the twins
// (TestInliningGuard, TestEscapeUnchanged and TestWovenBinaryHasHooks).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type named string

type stringer struct{ s string }

func (s stringer) String() string { return "stringer:" + s.s }

type record struct {
	Name  string `json:"name"`
	Count int    `json:"count,string"`
	Note  string `json:"note"`
}

// render uses the hooked paths of fmt: the buffer writes, the padding, the
// string and byte verbs, the methods and the format string.
func render(args []string) string {
	s := strings.Join(args, "|") + "-suffix"
	b := []byte(s)
	var out strings.Builder
	out.WriteString(fmt.Sprint("a=", s, "!"))
	out.WriteString(fmt.Sprintf("%s %v %q %x %10s|%-10s|%010d|%T|%p", s, s, s, s, s, s, len(s), s, &s))
	out.WriteString(fmt.Sprintf("%s %v %q %x %10s", b, b, b, b, b))
	out.WriteString(fmt.Sprintf("%s %v %q", named(s), stringer{s}, stringer{s}))
	out.WriteString(fmt.Sprintf("%#v %+v %d %!", s, record{Name: s}, []string{s}))
	out.WriteString(fmt.Errorf("wrapped: %w", io.EOF).Error())
	fmt.Fprintf(&out, "%s", s)
	return out.String()
}

// readAll uses io.ReadAll, bufio.(*Reader).Read, fill and ReadBytes.
func readAll(data string) (int, error) {
	all, err := io.ReadAll(strings.NewReader(data))
	if err != nil {
		return 0, err
	}
	// A small buffer: Read slides and refills the buffer.
	r := bufio.NewReaderSize(strings.NewReader(data), 16)
	total := 0
	for {
		line, err := r.ReadBytes('\n')
		total += len(line)
		if err != nil {
			break
		}
	}
	r = bufio.NewReaderSize(strings.NewReader(data), 16)
	chunk := make([]byte, 4)
	for {
		n, err := r.Read(chunk)
		total += n
		if err != nil {
			break
		}
	}
	// A large read goes straight to the reader.
	r = bufio.NewReaderSize(strings.NewReader(data), 16)
	large := make([]byte, 64)
	n, _ := r.Read(large)
	return len(all) + total + n, nil
}

// decode uses the hooked paths of encoding/json: the refill of the Decoder,
// the ",string" fields, and the strings with escapes.
func decode(text string) (int, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	count := 0
	for {
		var rec record
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				return count, nil
			}
			return count, err
		}
		count += rec.Count + len(rec.Name) + len(rec.Note)
	}
}

func main() {
	rendered := render(os.Args)
	lines := strings.Repeat("line of text\n", 20)
	n, err := readAll(lines)
	if err != nil {
		fmt.Println("read error:", err)
		os.Exit(1)
	}
	doc := strings.Repeat(`{"name":"a\nb\u00e9","count":"12","note":"plain"}`+"\n", 30)
	c, err := decode(doc)
	if err != nil {
		fmt.Println("decode error:", err)
		os.Exit(1)
	}
	if len(rendered) > 0 && n > 0 && c > 0 {
		fmt.Println("ok")
	}
}
