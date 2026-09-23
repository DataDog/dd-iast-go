//go:build tools

package tools

import (
	_ "github.com/DataDog/orchestrion" // integration

	_ "github.com/DataDog/dd-iast-go/iast/propagation"   // integration
	_ "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer" // integration
)
