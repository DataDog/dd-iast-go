module github.com/DataDog/dd-iast-go/benchmarks/overhead

go 1.25.5

tool (
	github.com/DataDog/orchestrion
	golang.org/x/perf/cmd/benchstat
)

require (
	github.com/DataDog/dd-iast-go v0.0.0
	github.com/DataDog/dd-trace-go/contrib/net/http/v2 v2.11.0-dev.0.20260724102042-cf24b817c453
	github.com/DataDog/dd-trace-go/v2 v2.11.0-dev.0.20260724102042-cf24b817c453
	github.com/DataDog/orchestrion v1.11.1-0.20260727153957-ca9d7e11be10
	golang.org/x/perf v0.0.0-20220722155237-ae9a248e26e8
)

replace github.com/DataDog/dd-iast-go => ../..
