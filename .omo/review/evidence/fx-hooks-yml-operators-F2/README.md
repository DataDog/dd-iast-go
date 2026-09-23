# fx-hooks-yml-operators-F2 evidence (independent verification)

Fixtures written by this node (NOT the finder's):
- `reviewf2/limits.go` - non-test, production-shaped package: `const maxLen = 1e3`
  used as `s[:maxLen]`, `b[0:2.0]`, `s[complex(1,0):3]`, `b[0:2:4.0]`.
- `reviewf2/limits_test.go` - behavior check (plain build passes).
- `typeprobe2/main.go` - independent go/types probe of the bound's resolved type.

Commands (run in a private copy of HEAD 2e23b46 at /tmp/ddiast-review/wt/fx-hooks-yml-operators-F2):
- plain:  GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -timeout 3m -count=1 ./reviewf2            -> plain-go1266.txt (ok)
- woven:  GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go tool orchestrion go test -timeout 3m -count=1 ./reviewf2 -> woven-go1266.txt (build failed)
- gen:    GOTOOLCHAIN=go1.26.6 go tool orchestrion go build -work ./reviewf2                    -> generated-limits.go
- probe:  GOTOOLCHAIN=go1.26.6 go run ./typeprobe2                                              -> typeprobe-go1266.txt
- go1.27: GOTOOLCHAIN=go1.27.0 go tool orchestrion go build -work ./reviewf2                    -> woven-go1270.txt
          (masked: the encoding/json aspect fails to weave on the 1.27 stdlib, unrelated defect)
Woven build peak RSS 338 MB (/usr/bin/time -l), well under 4 GB.
