// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command derived checks that the hooks of iast/propagation/text record their
// derived entries in a program that does not import iast/propagation/text
// (the hooks come only from the orchestrion.tool.go file of the module). It
// prints the attributed segments of 3 sink values.
package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
)

func main() {
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = request.MaxAnalyses
	_, scope, created := request.Begin(context.Background())
	if !created {
		fmt.Println("no request")
		os.Exit(1)
	}
	defer scope.Finish()
	a, ok := scope.Analysis()
	if !ok {
		fmt.Println("no analysis")
		os.Exit(1)
	}
	value, ok := a.TaintString(constants.OriginHttpRequestParameter, "q", "héllo wörld")
	if !ok {
		fmt.Println("no taint")
		os.Exit(1)
	}
	for _, sink := range []string{
		"q=" + strings.ToUpper(value),
		"q=" + url.QueryEscape(value),
		"q=" + strconv.Quote(value),
	} {
		var r request.Attribution
		a.AttributeString(sink, &r)
		for i := 0; i < r.N; i++ {
			s := r.Segments[i]
			name := "foreign"
			if src, ok := r.Source(i); ok {
				name = src.Name
			}
			fmt.Printf("%d-%d=%s ", s.Start, s.Start+s.Length, name)
		}
		fmt.Println()
	}
}
