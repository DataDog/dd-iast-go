# fx-prop-writer-F1: writer receiver owner-fanout bound

Verdict: **CONFIRMED.** A configured analysis limit above four lets one
`strings.Builder` retain one writer record per active owner, despite the
documented four-owner-per-receiver limit.

Scope covered: `internal/taint/propagation/writer.go`,
`internal/taint/store/writer.go`, `internal/taint/store/lookup.go`,
`iast/propagation/orchestrion.yml`, `iast/propagation/writer.go`, writer
tests, `README.md`, and `phase1/01-design-intent.md`.

## Verdict per finding

### prop-writer-F1

- Verdict: **CONFIRMED**
- Same root cause as any duplicate report describing receiver owner fanout:
  yes. The fault is the unchecked admission of a new input owner after the
  existing-receiver lookup has reached its four-result publication cap.

## Reproduction

Independent reproducer:
`.omo/review/evidence/fx-prop-writer-F1/own_reproducer_test.go`. It uses the
actual woven `strings.Builder.WriteString` call site rather than directly
calling the wrapper. It creates 60 live request owners (the supported configured
maximum is 64), taints one input per owner, and appends each input to one
pre-grown Builder.

```sh
cd /tmp/ddiast-review/wt/fx-prop-writer-F1
cp .omo/review/evidence/fx-prop-writer-F1/own_reproducer_test.go \
  iast/propagation/zz_fx_prop_writer_f1_test.go
GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 /usr/bin/time -l \
  go tool orchestrion go test -timeout 10m -count=1 \
  -run '^TestFXPropWriterF1ConfiguredOwnerFanout$' -v ./iast/propagation
```

Key captured output:

```text
owners=60 writer_records=60 process_charged_bytes=1967040
--- PASS: TestFXPropWriterF1ConfiguredOwnerFanout (0.01s)
PASS
```

The captured Go 1.26.6 output is
`.omo/review/evidence/fx-prop-writer-F1/go1.26.6.out.txt`.

I also tried Go 1.27.0. The woven build fails before this test runs because
the JSON hooks reference removed `encoding/json.Decoder` fields (`dec.r` and
`dec.d`); the key output is retained in
`.omo/review/evidence/fx-prop-writer-F1/go1.27.0.out.txt`. This does not
affect the Go 1.26.6 reproduction.

## Reachability

The direct Builder write is an advertised, woven propagation path. Ordinary
application code can trigger the violation by sharing a Builder across five or
more simultaneously active, sampled requests and configuring
`DD_IAST_MAX_CONCURRENT_REQUESTS` to at least five (the supported range is
0--64).

It is **not reachable under default configuration**: the default concurrent
analysis limit is two (`internal/config/config.go:75`), and owner finish
synchronously removes its writer states. Thus a shared Builder can have at most
two live tracked owners at the default setting (with 30% default sampling
reducing occurrence further).

This is not a documented limitation. The README and design intent explicitly
state a limit of four owners per receiver; they do not authorize exceeding it.

## Adjusted severity

**High (unchanged).** Global store capacity and the 8 MiB process charge still
bound the failure, so this is not unbounded growth; however, the documented
per-receiver owner bound is exceeded by 15x in the independent 60-owner run
(and by up to 16x at 64 owners), matching the review scale's large-factor bound
breach.

## Root cause

`internal/taint/propagation/writer.go:101-132`: `LookupWriterValue` returns at
most four existing receiver owners. The first loop updates those owners, but
the second loop (`writer.go:125-132`) independently calls `owner.UpdateWriter`
for an input snapshot owner not in that four-entry set. `Owner.UpdateWriter`
only enforces `MaxWriters` per owner (`internal/taint/store/writer.go:193-201`);
it has no receiver-global owner admission check.

## Minimal fix

Before creating writer state for an unseen input owner, perform a
receiver-global, synchronized admission claim capped at
`store.MaxSnapshotOwners`. Treat dirty or lock-contended existing states as
occupied and drop the new owner's writer provenance when full. Release the
claim when that owner's writer state is reset, invalidated, or finished. This
preserves host Builder behavior and keeps the existing per-owner `MaxWriters`
limit independent.
