// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command scopeprobe uses the three ReadValue calls of the v2-backed
// encoding/json: (*Decoder).Decode, checkValid (json.Valid), and
// (*Number).UnmarshalJSONFrom (json.Number). TestV2ReadValueHookScope builds
// it with Orchestrion and without, and compares the results.
//
// Each line with the prefix "result " must be the same in the woven and in
// the unwoven build. Each line with the prefix "taint " tells if a decoded
// string has taint.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

func main() {
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	ctx, scope, created := request.Begin(context.Background())
	if !created {
		fmt.Fprintln(os.Stderr, "no request scope")
		os.Exit(1)
	}
	defer scope.Finish()
	source := taint.Source{Origin: taint.OriginHttpRequestBody, Name: "scopeprobe"}

	// checkValid.
	for _, document := range []string{`{"value":"x"}`, `{"value":`, `[1,2,3]`, `"a" "b"`, ``} {
		tainted := taint.TaintBytes(ctx, source, []byte(document))
		fmt.Printf("result valid %q clean=%t tainted=%t\n", document, json.Valid([]byte(document)), json.Valid(tainted))
	}

	// (*Number).UnmarshalJSONFrom through json.Unmarshal.
	for _, document := range []string{`123`, `-1.5e3`, `"789"`, `"x"`, `null`, `true`, `{"n":42}`} {
		var number json.Number
		var object struct {
			N json.Number `json:"n"`
		}
		tainted := taint.TaintBytes(ctx, source, []byte(document))
		errNumber := json.Unmarshal(tainted, &number)
		errObject := json.Unmarshal(tainted, &object)
		fmt.Printf("result unmarshal %q number=%q error=%v object=%q error=%v\n", document, number, errNumber != nil, object.N, errObject != nil)
	}

	// (*Number).UnmarshalJSONFrom and the value document through
	// (*Decoder).Decode, on a reader of the request.
	const stream = `42 {"n":7,"s":"from-body"} {"n":"8","s":"second"} "x"`
	reader := strings.NewReader(stream)
	if !request.BindReader(ctx, reader) {
		fmt.Fprintln(os.Stderr, "the reader is not bound")
		os.Exit(1)
	}
	decoder := json.NewDecoder(reader)
	var first json.Number
	err := decoder.Decode(&first)
	fmt.Printf("result decode number=%q error=%v\n", first, err != nil)
	for range 2 {
		var item struct {
			N json.Number `json:"n"`
			S string      `json:"s"`
		}
		err = decoder.Decode(&item)
		fmt.Printf("result decode object n=%q s=%q error=%v\n", item.N, item.S, err != nil)
		fmt.Printf("taint decode object s=%t\n", taint.IsTaintedString(item.S))
	}
	var last json.Number
	err = decoder.Decode(&last)
	fmt.Printf("result decode number=%q error=%v\n", last, err != nil)
	number := json.NewDecoder(strings.NewReader(`1 2`))
	number.UseNumber()
	var values []any
	for number.More() {
		var value any
		err = number.Decode(&value)
		values = append(values, value)
	}
	fmt.Printf("result decode use-number=%v error=%v\n", values, err != nil)
}
