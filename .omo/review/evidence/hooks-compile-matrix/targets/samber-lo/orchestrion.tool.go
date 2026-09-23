//go:build tools

package lo

import (
	_ "github.com/DataDog/dd-iast-go"  // integration
	_ "github.com/DataDog/orchestrion" // integration
)
