//go:build tools

package fxrepro

import (
	_ "github.com/DataDog/dd-iast-go/iast/net/http" // integration
	_ "github.com/DataDog/orchestrion"              // integration
)
