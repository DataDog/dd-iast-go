//go:build tools

package main

import (
	_ "github.com/DataDog/dd-iast-go" // integration
	_ "github.com/DataDog/orchestrion" // integration
)
