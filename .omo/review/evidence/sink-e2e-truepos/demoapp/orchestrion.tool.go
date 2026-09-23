//go:build tools

package main

import (
	_ "github.com/DataDog/dd-iast-go"                      // integration: documented aggregate
	_ "github.com/DataDog/dd-trace-go/contrib/net/http/v2" // integration: server spans like a customer
	_ "github.com/DataDog/orchestrion"                     // integration
)
