# Root-module plugin compile reproducer

Created in the mandated private copy at
`/tmp/ddiast-review/wt/hooks-scope-root/scopefixtures/workspace`.

## Files

`go.work`:

```go
go 1.26.6

use (
	./app
	./dep
)
```

`app/go.mod`:

```go
module example.com/app

go 1.26.6

tool github.com/DataDog/orchestrion

require (
	example.com/dep v0.0.0
	github.com/DataDog/dd-iast-go v0.0.0
	github.com/DataDog/orchestrion v1.12.2-0.20260828141217-23afa71d6dcb
)

replace github.com/DataDog/dd-iast-go => ../../../
replace example.com/dep => ../dep
```

`app/orchestrion.tool.go`:

```go
//go:build tools

package app

import (
	_ "github.com/DataDog/orchestrion"

	_ "github.com/DataDog/dd-iast-go/iast/database/sql"
	_ "github.com/DataDog/dd-iast-go/iast/encoding/json"
	_ "github.com/DataDog/dd-iast-go/iast/os/exec"
	_ "github.com/DataDog/dd-iast-go/iast/propagation"
)
```

`app/cmd/plugin/plugin.go`:

```go
package main

import "strings"

func main() {}

func Upper(value string) string {
	return strings.ToUpper(value)
}
```

## Commands and captured output

The normal Go toolchain accepts the plugin:

```console
$ cd /tmp/ddiast-review/wt/hooks-scope-root/scopefixtures/workspace/app
$ GOTOOLCHAIN=go1.26.6 go build -buildmode=plugin -o ../app-plugin-plain.so ./cmd/plugin
$ echo $?
0
```

The configured instrumentation fails the same valid plugin build:

```console
$ GOTOOLCHAIN=go1.26.6 go tool orchestrion go build -buildmode=plugin -gcflags=all=-l -o ../app-plugin.so ./cmd/plugin
# example.com/app/cmd/plugin
resolving "github.com/DataDog/dd-iast-go/iast/database/sql": internal error: nats: maximum payload exceeded
exit status 1
$ echo $?
1
```

The failed resolution of `iast/database/sql` demonstrates that the
`package-filter: {root: true, pattern: "**"}`, `test-main: false`, `main`
bootstrap selector matches a root-module Go plugin. A plugin is a `package
main` build but is not excluded by any build-mode predicate.
