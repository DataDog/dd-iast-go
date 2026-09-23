# E1, E2, E4 captured output (fixture fx/app, full root integration set)

### E1 plain go plugin build (with func main)
```console
$ cd $WT/fx/app
$ GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go build -buildmode=plugin -o ../out/pluginmain-plain.so ./cmd/pluginmain
            59555840  maximum resident set size
exit status: 0
```

### E4 woven ordinary executable control
```console
$ cd $WT/fx/app
$ GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go build -o ../out/app ./cmd/app && ../out/app
""},"Graph Gophers GraphQL":{"instrumented":false,"available":false,"available_version":""},"GraphQL-Go GraphQL":{"instrumented":false,"available":false,"available_version":""},"HTTP":{"instrumented":false,"available":false,"available_version":""},"HTTP Router":{"instrumented":false,"available":false,"available_version":""},"HTTP Treemux":{"instrumented":false,"available":false,"available_version":""},"IBM sarama":{"instrumented":false,"available":false,"available_version":""},"Kafka (confluent)":{"instrumented":false,"available":false,"available_version":""},"Kafka (confluent) v2":{"instrumented":false,"available":false,"available_version":""},"Kafka v0":{"instrumented":false,"available":false,"available_version":""},"Kubernetes":{"instrumented":false,"available":false,"available_version":""},"LevelDB":{"instrumented":false,"available":false,"available_version":""},"Logrus":{"instrumented":false,"available":false,"available_version":""},"MCP":{"instrumented":false,"available":false,"available_version":""},"Memcache":{"instrumented":false,"available":false,"available_version":""},"MongoDB":{"instrumented":false,"available":false,"available_version":""},"MongoDB (mgo)":{"instrumented":false,"available":false,"available_version":""},"Negroni":{"instrumented":false,"available":false,"available_version":""},"PGX":{"instrumented":false,"available":false,"available_version":""},"Pub/Sub":{"instrumented":false,"available":false,"available_version":""},"Pub/Sub v2":{"instrumented":false,"available":false,"available_version":""},"Redigo":{"instrumented":false,"available":false,"available_version":""},"Redis":{"instrumented":false,"available":false,"available_version":""},"Redis v7":{"instrumented":false,"available":false,"available_version":""},"Redis v8":{"instrumented":false,"available":false,"available_version":""},"Redis v9":{"instrumented":false,"available":false,"available_version":""},"Rueidis":{"instrumented":false,"available":false,"available_version":""},"SQL":{"instrumented":false,"available":false,"available_version":""},"SQLx":{"instrumented":false,"available":false,"available_version":""},"Shopify sarama":{"instrumented":false,"available":false,"available_version":""},"Twirp":{"instrumented":false,"available":false,"available_version":""},"Valkey":{"instrumented":false,"available":false,"available_version":""},"Vault":{"instrumented":false,"available":false,"available_version":""},"Zap":{"instrumented":false,"available":false,"available_version":""},"Zerolog":{"instrumented":false,"available":false,"available_version":""},"chi":{"instrumented":false,"available":false,"available_version":""},"chi v5":{"instrumented":false,"available":false,"available_version":""},"echo v4":{"instrumented":false,"available":false,"available_version":""},"franz-go":{"instrumented":false,"available":false,"available_version":""},"gRPC":{"instrumented":false,"available":false,"available_version":""},"go-pg v10":{"instrumented":false,"available":false,"available_version":""},"go-restful v3":{"instrumented":false,"available":false,"available_version":""},"gqlgen":{"instrumented":false,"available":false,"available_version":""},"log/slog":{"instrumented":false,"available":false,"available_version":""},"miekg/dns":{"instrumented":false,"available":false,"available_version":""}},"partial_flush_enabled":false,"partial_flush_min_spans":1000,"orchestrion":{"enabled":true,"metadata":{"version":"v1.12.2-0.20260828141217-23afa71d6dcb"}},"feature_flags":[],"propagation_style_inject":"datadog,tracecontext,baggage","propagation_style_extract":"datadog,tracecontext,baggage","tracing_as_transport":false,"dogstatsd_address":"localhost:8125","data_streams_enabled":false,"otlp_traces_export_enabled":false,"otlp_metrics_export_enabled":false,"otlp_logs_export_enabled":false}
2026/09/23 15:47:30 Datadog Tracer v2.11.0-rc.1 ERROR: loading features: Get "http://localhost:8126/info": dial tcp 127. ...
exit status: 0
```
### E2 woven plugin build, cmd/pluginmain (declares func main), full root integration set
```console
$ cd $WT/fx/app
$ GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go build -buildmode=plugin -o ../out/pluginmain.so ./cmd/pluginmain
# example.com/app/cmd/pluginmain
resolving "github.com/DataDog/dd-iast-go/iast/crypto/cipher": internal error: nats: maximum payload exceeded
exit status 1
          2732802048  maximum resident set size
exit status: 1
```
### E3 woven plugin build, cmd/pluginnomain (NO func main, so no bootstrap aspect can match), full root integration set
```console
$ cd $WT/fx/app
$ GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go build -buildmode=plugin -o ../out/pluginnomain.so ./cmd/pluginnomain
.26.6.darwin-arm64/src/github.com/tinylib/msgp/msgp (from $GOROOT)
	/Users/eliott.bouhana/go/src/github.com/tinylib/msgp/msgp (from $GOPATH)
-: # github.com/DataDog/dd-iast-go/internal/taint/jsonbridge
go env GOMOD: in "/var/folders/zb/3gg9brcd3ys4_f10zztf2kq00000gp/T/go-build2923307535/b001/exe": `go env GOMOD` returned a blank string
/Users/eliott.bouhana/go/src/github.com/DataDog/dd-iast-go/internal/model/constants/origin_gen.go:6:2: cannot find package "github.com/tinylib/msgp/msgp" in any of:
	/Users/eliott.bouhana/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.6.darwin-arm64/src/github.com/tinylib/msgp/msgp (from $GOROOT)
	/Users/eliott.bouhana/go/src/github.com/tinylib/msgp/msgp (from $GOPATH)
-: # github.com/DataDog/dd-iast-go/internal/config/parser
go env GOMOD: in "/var/folders/zb/3gg9brcd3ys4_f10zztf2kq00000gp/T/go-build2923307535/b001/exe": `go env GOMOD` returned a blank string
-: # github.com/DataDog/dd-iast-go/internal/config/parser
go env GOMOD: in "/var/folders/zb/3gg9brcd3ys4_f10zztf2kq00000gp/T/go-build2923307535/b001/exe": `go env GOMOD` returned a blank string
/Users/eliott.bouhana/go/src/github.com/DataDog/dd-iast-go/internal/model/constants/origin_gen.go:6:2: cannot find package "github.com/tinylib/msgp/msgp" in any of:
	/Users/eliott.bouhana/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.6.darwin-arm64/src/github.com/tinylib/msgp/msgp (from $GOROOT)
	/Users/eliott.bouhana/go/src/github.com/tinylib/msgp/msgp (from $GOPATH)
/Users/eliott.bouhana/go/src/github.com/DataDog/dd-iast-go/internal/model/constants/origin_gen.go:6:2: cannot find package "github.com/tinylib/msgp/msgp" in any of:
	/Users/eliott.bouhana/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.6.darwin-arm64/src/github.com/tinylib/msgp/msgp (from $GOROOT)
	/Users/eliott.bouhana/go/src/github.com/tinylib/msgp/msgp (from $GOPATH)
-: # github.com/DataDog/dd-iast-go/internal/taint/writerbridge
go env GOMOD: in "/var/folders/zb/3gg9brcd3ys4_f10zztf2kq00000gp/T/go-build2923307535/b001/exe": `go env GOMOD` returned a blank string
-: # github.com/DataDog/dd-iast-go/internal/config/parser
go env GOMOD: in "/var/folders/zb/3gg9brcd3ys4_f10zztf2kq00000gp/T/go-build2923307535/b001/exe": `go env GOMOD` returned a blank string
-: # github.com/DataDog/dd-iast-go/internal/config/parser
go env GOMOD: in "/var/folders/zb/3gg9brcd3ys4_f10zztf2kq00000gp/T/go-build2923307535/b001/exe": `go env GOMOD` returned a blank string
/Users/eliott.bouhana/go/src/github.com/DataDog/dd-iast-go/internal/model/constants/origin_gen.go:6:2: cannot find package "github.com/tinylib/msgp/msgp" in any of:
	/Users/eliott.bouhana/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.6.darwin-arm64/src/github.com/tinylib/msgp/msgp (from $GOROOT)
	/Users/eliott.bouhana/go/src/github.com/tinylib/msgp/msgp (from $GOPATH)
/Users/eliott.bouhana/go/src/github.com/DataDog/dd-iast-go/internal/model/constants/origin_gen.go:6:2: cannot find package "github.com/tinylib/msgp/msgp" in any of:
	/Users/eliott.bouhana/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.6.darwin-arm64/src/github.com/tinylib/msgp/msgp (from $GOROOT)
	/Users/eliott.bouhana/go/src/github.com/tinylib/msgp/msgp (from $GOPATH)
/Users/eliott.bouhana/go/src/github.com/DataDog/dd-iast-go/internal/model/constants/origin_gen.go:6:2: cannot find package "github.com/tinylib/msgp/msgp" in any of:
	/Users/eliott.bouhana/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.6.darwin-arm64/src/github.com/tinylib/msgp/msgp (from $GOROOT)
	/Users/eliott.bouhana/go/src/github.com/tinylib/msgp/msgp (from $GOPATH)
-: # github.com/DataDog/dd-iast-go/internal/taint/operatorbridge
go env GOMOD: in "/var/folders/zb/3gg9brcd3ys4_f10zztf2kq00000gp/T/go-build2923307535/b001/exe": `go env GOMOD` returned a blank string
-: # github.com/DataDog/dd-iast-go/internal/taint/writerbridge
go env GOMOD: in "/var/folders/zb/3gg9brcd3ys4_f10zztf2kq00000gp/T/go-build2923307535/b001/exe": `go env GOMOD` returned a blank string
exit status 1
            81346560  maximum resident set size
exit status: 1
```