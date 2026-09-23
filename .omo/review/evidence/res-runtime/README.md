# res-runtime evidence

Setup (scratch copy, removed after the run):

    mkdir -p W/research && git -C <orchestrion> archive eliottness/iast-testing runtime/taint | tar -x -C W/research
    rm -rf W/research/runtime/taint/instrument
    git -C <orchestrion> show eliottness/iast-testing:go.mod > W/research/go.mod   # same for go.sum

- research_race.out.txt: research unit tests under -race (pass).
- zz_review_stale_test.go + stale_capacity.out.txt: copy into W/research/runtime/taint/ and run
  `GOFLAGS=-mod=mod go test -count=1 -run Test_ReviewStaleCapacityTaint -v ./runtime/taint/` (fails = pitfall reproduced).
- alias_probe.go + alias_probe.out.txt: standalone module (`go 1.26`), run with `GOTOOLCHAIN=go1.26.6 go run .` and `GOTOOLCHAIN=local go run .` (go1.27.0).
