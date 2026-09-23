# Root, workspace, replacement, and vendor scope reproducer

The workspace layout contains a root application module `example.com/app` and
a sibling workspace dependency `example.com/dep`. Both define the same direct
call:

```go
func Upper(value string) string {
	return strings.ToUpper(value)
}
```

The application requires the dependency through:

```go
require example.com/dep v0.0.0
replace example.com/dep => ../dep
```

## Member-module invocation

```console
$ cd /tmp/ddiast-review/wt/hooks-scope-root/scopefixtures/workspace/app
$ GOTOOLCHAIN=go1.26.6 go tool orchestrion go build -gcflags=all=-l -o ../app-from-member ./cmd/app
$ ../app-from-member
LOCAL DEPENDENCY
```

The local module receives propagation wrapping:

```console
$ go tool objdump -s example.com/app/own.Upper ../app-from-member
TEXT example.com/app/own.Upper(SB) .../app/own/upper.go
  upper.go:6  CALL github.com/DataDog/dd-iast-go/iast/propagation.StringsToUpper(SB)
```

The sibling workspace dependency does not:

```console
$ go tool objdump -s example.com/dep.Upper ../app-from-member
TEXT example.com/dep.Upper(SB) .../dep/upper.go
  upper.go:6  CALL strings.ToUpper(SB)
```

## Vendored workspace

```console
$ cd /tmp/ddiast-review/wt/hooks-scope-root/scopefixtures/workspace
$ GOTOOLCHAIN=go1.26.6 go work vendor
$ cd app
$ GOTOOLCHAIN=go1.26.6 go tool orchestrion go build -mod=vendor -gcflags=all=-l -o ../app-from-vendor ./cmd/app
$ ../app-from-vendor
LOCAL DEPENDENCY
```

The vendored binary has the same scope boundary:

```console
$ go tool objdump -s example.com/app/own.Upper ../app-from-vendor
  upper.go:6  CALL github.com/DataDog/dd-iast-go/iast/propagation.StringsToUpper(SB)

$ go tool objdump -s example.com/dep.Upper ../app-from-vendor
  upper.go:6  CALL strings.ToUpper(SB)
```

## Workspace-root invocation

Running `go tool orchestrion` at a `go.work` root with no package/tool file
fails loudly rather than silently dropping advice:

```console
$ cd /tmp/ddiast-review/wt/hooks-scope-root/scopefixtures/workspace
$ GOTOOLCHAIN=go1.26.6 go tool orchestrion go build -gcflags=all=-l -o app-from-workspace-root ./app/cmd/app
loading injector configuration: in ".": no Go files found, was expecting at least orchestrion.tool.go: -: no Go files in .../workspace
go: error obtaining buildID for go tool compile: exit status 255
exit status 1
```
