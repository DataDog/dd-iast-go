// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command nohook imports nothing from dd-iast-go. It runs the 8 hooked runtime
// operations, so it checks that a woven runtime links (with the default
// linker check of linknames) and runs (TestWovenProgramLinks).
package main

import (
	"fmt"
	"os"
)

func main() {
	s := os.Args[0] + "-suffix"
	b := []byte(s + "-bytes")
	r := []rune(string(b))
	out := string(r) + string([]byte(s))
	grown := append(b[:len(b):len(b)], '!')
	var buf []byte
	for i := range 40 {
		buf = append(buf, byte(i))
		_ = cap(buf)
	}
	if len(out) > len(s) && len(grown) == len(b)+1 && len(buf) == 40 {
		fmt.Println("ok")
	}
}
