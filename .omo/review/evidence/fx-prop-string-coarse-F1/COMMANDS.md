# Independent reproduction

Target: `2e23b4614320defd0d32177a69888dcab73f4d11`.

`main.go` is independently authored, not copied from either phase-2 finder.
It belongs at `iast/integration/testapp/cmd/fx-coarse/main.go` in an isolated
copy of the target. The existing nested module supplies Orchestrion and tracer
configuration; the executable does not import SQL sink registration manually.

## Setup

```sh
ROOT=/Users/eliott.bouhana/go/src/github.com/DataDog/dd-iast-go
WORK=/tmp/ddiast-review/wt/fx-prop-string-coarse-F1
EVIDENCE="$ROOT/.omo/review/evidence/fx-prop-string-coarse-F1"
mkdir -p "$WORK"
rsync -a --exclude .git --exclude .omo "$ROOT/" "$WORK/"
mkdir -p "$WORK/iast/integration/testapp/cmd/fx-coarse"
cp "$EVIDENCE/main.go" "$WORK/iast/integration/testapp/cmd/fx-coarse/main.go"
cd "$WORK/iast/integration/testapp"
```

## Build and execute

```sh
GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 /usr/bin/time -l timeout 900 \
  go tool orchestrion go build -o "$WORK/fx-coarse-126" ./cmd/fx-coarse

for mode in stringer error formatter gostring sprint sprintln bytes explicit clean direct; do
  printf '\nMODE=%s\n' "$mode"
  DD_TRACE_STARTUP_LOGS=false timeout 30 "$WORK/fx-coarse-126" "$mode"
  printf 'EXIT=%s\n' "$?"
done

GOFLAGS=-p=4 GOTOOLCHAIN=go1.27.0 /usr/bin/time -l timeout 900 \
  go tool orchestrion go build -o "$WORK/fx-coarse-127" ./cmd/fx-coarse
```

Every mode gets a new process, preserving default deduplication. A real HTTP
request taints `URL.Query().Get("sort")`; the byte case uses `io.ReadAll` on the
request body. Only request sampling is changed, from the logged default of
30 percent to 100 percent, to avoid nondeterminism. Defaults for enablement,
concurrency, vulnerability quota, redaction, and deduplication are retained.

The recording driver replaces only the external database, after the real
`database/sql.DB.ExecContext` boundary. It checks that the query received by the
driver equals the formatted value. Source discovery, formatting wrappers, SQL
reporting, redaction, and span event publication are real woven code. The mock
tracer captures the finished span locally rather than sending it to an agent.
A completion channel signals after span finish; no sleeps or polling are used.

For constant-only queries the program asserts zero ranges and zero vulnerability
events and exits 1 on a false positive. `explicit` calls `String()` before
formatting; `clean` passes an untainted named value. Both are negative controls.
`direct` passes the original tainted string and asserts that the SQL injection
event is present. The method counter must equal one for every method case.

## Cleanup

```sh
rm -rf /tmp/ddiast-review/wt/fx-prop-string-coarse-F1
test ! -e /tmp/ddiast-review/wt/fx-prop-string-coarse-F1
```
