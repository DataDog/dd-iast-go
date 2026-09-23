#!/bin/bash
# usage: wire.sh <dir> <pkgname> [extra go get args...]
set -uo pipefail
W=/tmp/ddiast-review/wt/hooks-compile-matrix
d=$1; pkg=$2; shift 2
cd "$W/$d" || exit 1
export GOTOOLCHAIN=go1.26.6 GOFLAGS=-mod=mod
go mod edit -dropreplace github.com/DataDog/dd-iast-go 2>/dev/null
go mod edit -replace github.com/DataDog/dd-iast-go=$W/dd-iast-go
go mod edit -require github.com/DataDog/dd-iast-go@v0.0.0-00010101000000-000000000000
go get github.com/DataDog/orchestrion@v1.12.2-0.20260828141217-23afa71d6dcb "$@" || exit 2
if [ ! -f orchestrion.tool.go ]; then
cat > orchestrion.tool.go <<EOF
//go:build tools

package $pkg

import (
	_ "github.com/DataDog/orchestrion" // integration
)
EOF
fi
grep -q '"github.com/DataDog/dd-iast-go"' orchestrion.tool.go || sed -i '' 's#_ "github.com/DataDog/orchestrion"#_ "github.com/DataDog/dd-iast-go" // integration\
	_ "github.com/DataDog/orchestrion"#' orchestrion.tool.go
go mod edit -tool github.com/DataDog/orchestrion
go mod tidy || exit 3
echo "--- go.mod key lines"; grep -E "^go |dd-iast-go|orchestrion v|dd-trace-go/v2 v" go.mod
echo "--- tool.go"; grep '_ "' orchestrion.tool.go
