// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command derived does not import iast/propagation/*: the hooks of package
// stream are woven into fmt by the Orchestrion aspects only. It taints a
// request parameter, formats it with %q (a generated output: the hook of
// fmt taints it as a whole, with a derived entry of the parameter), and
// prints the attribution of the result (TestDerivedInProgram). The derived
// entry works through the push linkname __dd_iast_propbridge.derived.
package main

import (
	"context"
	"fmt"
	"os"

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
	analysis, ok := scope.Analysis()
	if !ok {
		fmt.Println("no analysis")
		os.Exit(1)
	}
	// A heap copy of the parameter value (a constant has no taint bits).
	raw := make([]byte, len("robert"))
	copy(raw, "robert")
	value, ok := analysis.TaintString(constants.OriginHttpRequestParameter, "q", string(raw))
	if !ok {
		fmt.Println("no taint")
		os.Exit(1)
	}
	quoted := fmt.Sprintf("%q", value)
	var attribution request.Attribution
	analysis.AttributeString(quoted, &attribution)
	fmt.Printf("value %s\n", quoted)
	for i := 0; i < attribution.N; i++ {
		segment := attribution.Segments[i]
		label := "foreign"
		if source, ok := attribution.Source(i); ok {
			label = source.Origin.String() + ":" + source.Name
		}
		fmt.Printf("%d-%d=%s\n", segment.Start, segment.Start+segment.Length, label)
	}
}
