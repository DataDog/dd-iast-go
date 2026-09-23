#!/usr/bin/env bash
# Independent reproducer for hooks-scope-root-F1 (fx-hooks-scope-root-F1).
# Layout: $WT = private rsync copy of dd-iast-go @2e23b46; fixtures under $WT/fx/<name>
# with go.mod "module example.com/app", "replace github.com/DataDog/dd-iast-go => ../..",
# "tool github.com/DataDog/orchestrion" (v1.12.2-0.20260828141217-23afa71d6dcb).
#   fx/app        orchestrion.tool.go = the 13 imports of the repo-root orchestrion.tool.go (full set)
#   fx/sqlonly    orchestrion.tool.go = orchestrion + iast/database/sql
#   fx/traceronly orchestrion.tool.go = orchestrion + dd-trace-go/v2/ddtrace/tracer (no dd-iast-go)
# Packages (copied into each fixture):
#   cmd/pluginmain/plugin.go   : package main; import "strings"; func main() {}; func Upper(v string) string { return strings.ToUpper(v) }
#   cmd/pluginnomain/plugin.go : same without func main
#   cmd/app/main.go            : ordinary executable
#   cmd/cshared/main.go        : package main; import "C"; //export Answer; func main() {}
set -u
export GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4
cd "$WT/fx/app"
go build -buildmode=plugin -o ../out/pluginmain-plain.so ./cmd/pluginmain                  # E1 -> 0
go tool orchestrion go build -o ../out/app ./cmd/app                                       # E4 -> 0
go tool orchestrion go build -buildmode=plugin -o ../out/pluginmain.so ./cmd/pluginmain    # E2 -> 1
go tool orchestrion go build -buildmode=plugin -o ../out/pluginnomain.so ./cmd/pluginnomain # E3 -> 1
cd "$WT/fx/sqlonly"
go tool orchestrion go build -buildmode=plugin -o ../out/s1.so ./cmd/pluginmain            # E5 -> 1
go tool orchestrion go build -buildmode=plugin -o ../out/s2.so ./cmd/pluginnomain          # E5b -> 0
go build -buildmode=c-shared -o ../out/c0.dylib ./cmd/cshared                              # E7a
go tool orchestrion go build -buildmode=c-shared -o ../out/c1.dylib ./cmd/cshared          # E7b
cd "$WT/fx/traceronly"
go tool orchestrion go build -buildmode=plugin -o ../out/t1.so ./cmd/pluginmain            # E6 -> 1
go tool orchestrion go build -buildmode=plugin -o ../out/t2.so ./cmd/pluginnomain          # E6b -> 0
