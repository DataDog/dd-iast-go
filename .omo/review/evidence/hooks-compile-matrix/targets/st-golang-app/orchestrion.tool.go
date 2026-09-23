//go:build tools

package weblog

import (
	_ "github.com/DataDog/dd-iast-go" // integration
	_ "github.com/DataDog/orchestrion" // integration
)
