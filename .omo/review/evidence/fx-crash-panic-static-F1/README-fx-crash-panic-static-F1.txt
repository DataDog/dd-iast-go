Evidence for phase3/fx-crash-panic-static-F1 (independent verification of crash-panic-static-F1).

- initcrash2/            MY reproducer sources: module github.com/zzz/initcrash2.
                         fp/fp.go compiles a regexp and calls sha1.New() inside init().
- initcrash2-default.out.txt       default env -> panic (RC 2) in fp.init.0 via sha1.New hook.
- initcrash2-disabled.out.txt     DD_IAST_ENABLED=false -> RC 0 (config gate escape hatch).
- initcrash2-inittrace.out.txt     GODEBUG=inittrace=1: internal/config initializes, tracer/spans do NOT, then panic.
- initcrash-v1-nocrash.out.txt     control layout: hashing package initialized before internal/config -> hook gated off, no crash.
                                   Shows the crash window is [internal/config init .. internal/spans/tracer init] as claimed.
- finder-repro-rerun.out.txt      unmodified rerun of the finder's initorder-repro in this node's private copy: RC 2 panic.
- (repro/, repro.out.txt are from a different node sharing this directory; left untouched.)

Build: GOFLAGS='-p=4 -mod=mod' GOTOOLCHAIN=go1.26.6 GOPROXY=off /usr/bin/time -l go tool orchestrion go build -o <bin> .
Peak RSS observed: 438 MB (initcrash2 warm cache ~50 MB footprint reported by time), 438 MB for initorder — all < 4 GB.
