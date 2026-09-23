sink-e2e-truepos evidence
=========================
demoapp/            woven vulnerable demo (package main: main.go, handlers.go, driver.go, orchestrion.tool.go, go.mod/go.sum)
demoapp/cmd/driver  plain-built driver: fake trace-agent (advertises span_meta_structs), launches the woven demo,
                    drives it over real HTTP, decodes meta_struct (msgpack) or _dd.iast.json, asserts expectations.

Reproduce (in a private copy of the repo at HEAD 2e23b46; demoapp/ placed at <copy>/demoapp so `replace => ../` resolves):
  cd <copy>/demoapp
  export GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4
  go mod tidy
  go build -o ../driver ./cmd/driver
  /usr/bin/time -l go tool orchestrion go build -o ../demo .      # woven build, ~40s, max RSS ~455 MB
  cd .. 
  ./driver -bin ./demo -mode agent -out agent-results.json            # real tracer -> fake agent, meta_struct channel (default dedup ON)
  ./driver -bin ./demo -mode mock  -out mock-results.json             # mocktracer, _dd.iast.json fallback channel
  ./driver -bin ./demo -mode agent -nodedup -out nodedup-results.json # dedup OFF (needed for same-location variants e.g. /sql/login)
  ./driver -bin ./demo -mode agent -phase conc -out conc-results.json # 32 overlapping requests (16 tainted/16 clean)

Files: *-output.txt (driver verdict lines), *-results.json (per-case decoded event), *-results.spans.json (raw server spans),
build.log (orchestrion build + /usr/bin/time -l).
Case names: "neg-*" must not report; "doc-*"/"obs-*" are documented-limitation/observation probes; others are true positives.
