// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command hooked imports nothing from dd-iast-go. It uses all the hooked
// paths of package jsonv2 (and, without GOEXPERIMENT=jsonv2, the json paths
// of package stream) through encoding/json, so that the linker keeps the
// hooks and the twins (TestInliningGuard, TestEscapeUnchanged and
// TestVariantBuilds).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

type record struct {
	Name  string            `json:"name"`
	Count int               `json:"count,string"`
	Note  string            `json:"note"`
	Tags  []string          `json:"tags"`
	Meta  map[string]string `json:"meta"`
	Any   any               `json:"any"`
}

// decode uses the Decoder: the buffer reads, slides and grows (fetch), the
// strings with escapes (AppendUnquote) and the strings of the cache
// (makeString).
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
		count += rec.Count + len(rec.Name) + len(rec.Note) + len(rec.Tags) + len(rec.Meta)
	}
}

// unmarshal uses json.Unmarshal (decoded in place) and Token.
func unmarshal(text string) (int, error) {
	var rec record
	if err := json.Unmarshal([]byte(text), &rec); err != nil {
		return 0, err
	}
	dec := json.NewDecoder(strings.NewReader(text))
	tokens := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		if _, ok := tok.(string); ok {
			tokens++
		}
	}
	return len(rec.Name) + tokens, nil
}

func main() {
	one := `{"name":"a\nb\u00e9","count":"12","note":"plain","tags":["x1","y\t2"],"meta":{"k1":"v1"},"any":{"z":["w"]}}`
	c, err := decode(strings.Repeat(one+"\n", 30))
	if err != nil {
		fmt.Println("decode error:", err)
		os.Exit(1)
	}
	u, err := unmarshal(one)
	if err != nil {
		fmt.Println("unmarshal error:", err)
		os.Exit(1)
	}
	if c > 0 && u > 0 {
		fmt.Println("ok")
	}
}
