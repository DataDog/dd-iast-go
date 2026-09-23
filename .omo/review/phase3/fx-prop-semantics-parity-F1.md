# fx-prop-semantics-parity-F1: formatted Stringer field loses taint

## Verdict per finding

**prop-semantics-parity-F1: CONFIRMED.** On HEAD `2e23b46`, a woven
root-application `fmt.Sprintf` call formats a struct whose `String()` returns
its tainted field. The SQL text contains that field but has no provenance.
Only one finding was submitted here, so there is no duplicate to merge.

## Reproduction

Independent reproducer:
`.omo/review/evidence/fx-prop-semantics-parity-F1/review_f1_test.go`;
captured output:
`.omo/review/evidence/fx-prop-semantics-parity-F1/review_f1.out.txt`.
The test uses the existing deterministic request/source setup, an eligible
application-package `fmt.Sprintf` call, and the SQL sink's actual evidence
collector. To rerun from the main checkout without building there:

```sh
mkdir -p /tmp/ddiast-review/wt
rsync -a --exclude .git --exclude .omo ./ /tmp/ddiast-review/wt/fx-prop-semantics-parity-F1/
cp .omo/review/evidence/fx-prop-semantics-parity-F1/review_f1_test.go \
  /tmp/ddiast-review/wt/fx-prop-semantics-parity-F1/iast/propagation/review_f1_test.go
cd /tmp/ddiast-review/wt/fx-prop-semantics-parity-F1
/usr/bin/time -l env GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 \
  go tool orchestrion go test -timeout 8m -count=1 \
  -run '^TestReviewF1_' -v ./iast/propagation
```

The command exits 1 because the regression assertion fails, not because
weaving or compilation fails:

```text
query="SELECT * FROM users WHERE 1=1 --" input_tainted=true output_tainted=false sql_collection=0
expected: 0x1
actual  : 0x0
--- FAIL: TestReviewF1_StringerFieldReachesSQL_whenFormattedByApplication
```

Maximum resident set size was 350,093,312 bytes, below the brief's 4 GiB
build-memory reporting threshold.

## Reachability

Yes, on the supported Go 1.26.6 toolchain, for an admitted request under
default configuration (sampling defaults to 30%, and the ordinary root
application call matches `iast/propagation/orchestrion.yml:715-722`).
The reproducer forces admission solely to make the test deterministic.
`README.md` advertises direct `fmt.Sprint*` propagation and documents the
direct-call limitation, but it does **not** exclude Stringer arguments or
tainted fields. The phase-1 design-intent map likewise documents a coarse
formatting policy, not omission of emitted Stringer values. An actual
`database/sql` sink invokes `evidence.CollectString` and returns without
reporting unless it yields `StatusCollected`
(`iast/database/sql/sql.go:34-48`); the reproducer observes `StatusNone`.
Go 1.27.0 was not needed to establish reachability on the pinned supported
toolchain and was not tested.

## Adjusted severity

**High (unchanged):** a supported direct formatting path silently loses SQL
injection provenance and prevents the SQL sink from reporting; this is the
brief's wrong-provenance-on-a-supported-path category.

## Root cause

`iast/propagation/coarse.go:54-56` formats first, then passes only the
original arguments to `CoarseFormattedString`.
`internal/taint/propagation/string_coarse.go:115-130` inspects each
top-level argument with `formatArgumentKey`; that function accepts only
string or `[]byte` kinds (`string_coarse.go:203-219`), rejecting the struct.
The tainted string returned by its `String()` is seen only inside
`fmt.Sprintf`, not by propagation. With zero collected owners,
`publishCoarseOwners` returns the untainted result unchanged
(`string_coarse.go:175-179`). This is one missing-emitted-value attribution
mechanism, not a separate SQL collector bug.

## Minimal fix

Capture provenance from values actually emitted by `fmt` during its **single**
formatting pass, including the result of `String()`/`Format`, then associate
those contributions with the output. Preserve native method invocation
count, result, and side effects; do not call user formatters again or
indiscriminately taint output from every struct field. Bound the work by the
existing input, owner, and result limits.
