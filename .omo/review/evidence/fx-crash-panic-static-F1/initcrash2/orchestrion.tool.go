//go:build tools

package main

import (
	_ "github.com/DataDog/orchestrion"

	_ "github.com/DataDog/dd-iast-go/iast/bufio"
	_ "github.com/DataDog/dd-iast-go/iast/crypto/cipher"
	_ "github.com/DataDog/dd-iast-go/iast/crypto/hash"
	_ "github.com/DataDog/dd-iast-go/iast/database/sql"
	_ "github.com/DataDog/dd-iast-go/iast/encoding/json"
	_ "github.com/DataDog/dd-iast-go/iast/io"
	_ "github.com/DataDog/dd-iast-go/iast/net/http"
	_ "github.com/DataDog/dd-iast-go/iast/net/url"
	_ "github.com/DataDog/dd-iast-go/iast/os/exec"
	_ "github.com/DataDog/dd-iast-go/iast/propagation"
	_ "github.com/DataDog/dd-iast-go/taint"
	_ "github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)
