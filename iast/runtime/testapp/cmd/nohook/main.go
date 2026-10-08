// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command nohook does not import dd-iast-go. It runs the 6 hooked runtime
// operations, so it checks that a woven runtime links and runs with the
// default linker check (-checklinkname=1).
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
	fmt.Println(len(out) > len(s))
}
