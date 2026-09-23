# fx-hooks-io-bufio-F1: adversarial verification of hooks-io-bufio-F1

## Verdict per finding

**hooks-io-bufio-F1: CONFIRMED, severity High (unchanged).**

The mechanism is real at HEAD 2e23b46. I reproduced it end to end with my own reproducer: a woven `net/http` server, the real bufio/io hooks, the real `database/sql` sink, and mocktracer spans with default redaction. I also reproduced it through the internal API. Both runs used Go 1.26.6.
- **In-request false positive.** A clean constant, read through a `bufio.Reader` that was `Reset` after being built over `r.Body`, was reported as `SQL_INJECTION` with an `http.request.body` source. A control that reads the same constant through a fresh reader reported nothing.
- **Cross-owner attribution.** Request B reused a pooled reader that request A had created, while A was still active. B's clean internal query was tainted and reported. The data was published as a source of owner A: A's source count went from 1 to 2, and B's stayed at 0.

One finder sub-claim is **refuted**: "reports ... even if the second request was sampled out or was never admitted". `ReportTainted` returns early for any request scope that is not `DecisionActive` (`internal/vulnerability/tainted.go:45-47`), so sampled-out and unadmitted requests do not report. The foreign-owner reporting path does exist for contexts with no request scope, such as background goroutines or `context.Background()`. An earlier run of this node reproduced that path (see below). The refutation does not change the rating.

## Reproduction

All runs happened in a private copy at `/tmp/ddiast-review/wt/fx-hooks-io-bufio-F1`, now deleted. Evidence is under `.omo/review/evidence/fx-hooks-io-bufio-F1/`.

**Reproducer 1 (woven end to end, my files):** `testapp_zz_fx_reset.go` holds customer-shaped handler code. It sits in the non-test root package because the pinned injector's root filter skips the external `_test` package for operator advice (`iast/integration/testapp/chains.go:22-23`). My first attempt put the code in the `_test` file, and `string(q)` then stayed untainted. `testapp_zz_fx_reset_reader_test.go` holds the server and assertions. The pool is a mutex-guarded free list with the same `Get` (`Reset` on a hit, `bufio.NewReader` on a miss) and `Put` (`Reset(nil)`) shape as `net/http.newBufioReader`. I used it instead of `sync.Pool` so reuse across goroutines is deterministic.

```
cp testapp_zz_fx_reset.go iast/integration/testapp/zz_fx_reset.go
cp testapp_zz_fx_reset_reader_test.go iast/integration/testapp/zz_fx_reset_reader_test.go
cd iast/integration/testapp && GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -timeout 15m -count=1 -v -run TestFX .
```
Key lines from `e2e-go1.26.6.out.txt`:
```
diag reset body="name=alice" body-tainted=true q-tainted=true query="SELECT 1 FROM clean_constant" query-ranges={"Origin":"http.request.body",...,"Value":"SELECT 1 FROM clean_constant"}
diag control q-tainted=false query="SELECT 1 FROM clean_constant" query-ranges=
case=in-request-reset vuln[0] type=SQL_INJECTION evidence={"valueParts":[{"pattern":"abcdefghijklmnopqrstuvwxyzAB","redacted":true,"source":0}]}
case=in-request-reset source[0]={"origin":"http.request.body","pattern":"abcdefghijklmnopqrstuvwxyzAB","redacted":true}
case=in-request-control summary vulns=0 sources=0
diag A body="body_of_A=1" tainted=true
diag B internal q-tainted=true query="SELECT 3 FROM b_internal_clean" query-ranges={"Origin":"http.request.body",...,"Value":"SELECT 3 FROM b_internal_clean"}
case=pooled-B vuln[0] type=SQL_INJECTION evidence={"valueParts":[{"pattern":"abcdefghijklmnopqrstuvwxyzABCD","redacted":true,"source":0}]}
case=pooled-B source[0]={"origin":"http.request.body","pattern":"abcdefghijklmnopqrstuvwxyzABCD","redacted":true}
```
The redacted pattern lengths are 28 and 30. Those match `SELECT 1 FROM clean_constant` and `SELECT 3 FROM b_internal_clean` exactly, so the reported source value is the constant itself. Peak RSS was 0.37 GB.

**Reproducer 2 (internal API and owner lifetime, my file `iast_io_zz_fx_test.go`, placed in `iast/io/`):**
`GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -timeout 15m -count=1 -v -run TestFXResetKeepsStaleOwner ./iast/io/` produced `internal-go1.26.6.out.txt`:
```
fx case=reset-while-owner-active tainted=true ownerA.sources 1->2 ownerB.sources=0
fx case=reset-after-owner-finish tainted=false
```
The stale binding lasts only as long as the constructing owner, and nothing leaks past finish.

**Finder reproducer re-run** (`finder-repro-rerun-go1.26.6.out.txt`): the output is identical to the finder's `woven.out.txt`, covering `bufio.Reset`, `LimitedReader.R`, and cross-owner with A's source count going from 1 to 2.

**Earlier run of this node:** these files are in the same directory, with timestamps from 16:58 to 17:04: `zz_fx_f1*.go`, `woven-go1.26.6.out.txt`, and `iastio.out.txt`. That run also reproduced a background goroutine that uses `context.Background()`. It read a constant through the reused reader, then ran SQL, and the result was `span=req/a vuln=SQL_INJECTION source={"origin":"http.request.body","value":"SELECT name FROM constant_table"}`. The vulnerability landed on request A's trace even though A never executed SQL. That is consistent with the `tainted.go:45-47` gate, which lets scope-less contexts through.

**Go 1.27.0:** every woven build fails before any test runs, both the testapp and `./iast/io`. The error is `# encoding/json ... dec.r undefined (type *Decoder has no field or method r)`, recorded in `e2e-go1.27.0.out.txt` and `internal-go1.27.0.out.txt`. That is a separate compile break. F1 cannot be exercised on 1.27.0 until it is fixed, but the mechanism does not depend on the toolchain: the YAML hooks and binding table are the same, and `bufio.Reader.Reset` and `io.ReadAll` have the same shape.

## Reachability

- **Default config on Go 1.26.6: yes.** IAST must be enabled, and the constructing request must be sampled (30% by default) and admitted. The trigger is ordinary code: a `bufio.Reader` built with `bufio.NewReader(r.Body)`, or over any bound reader such as a `MaxBytesReader` or `LimitReader` of the body, and later `Reset(other)` while that request is still active, followed by `io.ReadAll(br)` or `json.NewDecoder(br)`. `CloneReaderBytes` uses the same lookup (`reader.go:45-63`). The realistic form is a pool of `bufio.Reader`s that constructs on a miss. The creating request's reader goes back to the pool mid-handler or through a `defer Put`, and owner finish runs after the handler returns, so concurrent reuse lands in that window under load. The in-request `Reset` to another source is legal but less common. `LimitedReader.R` reassignment is rare.
- **Where it reports:** on the reusing request's span if that request is active, or on the constructing request's span if the sink runs without a request scope. Sampled-out or unadmitted reusers do not report (refuted sub-claim).
- **Documented? No.** README "Propagation coverage" and the reader-retention paragraph (README:70-77), plus `01-design-intent.md:73,170,182-183`, document the bounds and the intent to clean up associations. None of them mention `Reset` or rewrapping keeping a stale binding. The behavior violates product rule 4: no false taint, and no bleed across requests or owners.

## Adjusted severity

**High, unchanged.** This is wrong provenance on a supported path (`bufio.NewReader` → `io.ReadAll` → `database/sql`). It produces false-positive SQLi from hard-coded constants and attributes taint to the wrong owner, which matches the brief's High definition exactly. It is not Critical, because host results are unchanged and bindings are released at owner finish.

## Root cause (file:line)

- `iast/bufio/orchestrion.yml:15-34`: only `NewReaderSize` is hooked. There is no aspect for `(*bufio.Reader).Reset` (Go `bufio.go:74`), and nothing can observe an assignment to `(*io.LimitedReader).R`.
- `internal/taint/request/reader.go:29-39`: `PropagateReader` binds the wrapper address to every owner of the input once, at construction.
- `internal/taint/store/binding.go:166-203` (`bind`) and `:95-108` (`BindObjectValue`): the key is only the wrapper `pointer`. There is no unbind API. Entries are cleared only by `bindingTable.reset()` at owner finish (`binding.go:232-239`).
- `internal/taint/request/reader.go:67-88`: `ReadAllBytes` adopts the whole result as an `http.request.body` source for every owner still bound to the wrapper, whatever the wrapper currently reads from.

## Minimal fix

1. Add a `bufio.(*Reader).Reset` aspect (`function-body`, receiver `*bufio.Reader`, name `Reset`) with the advice `defer func(){ if b != r { iastiobridge.Rebind(r, b) } }()`. `Rebind` does two things. First, it unbinds `b` as a reader from every active owner, using a new `store.UnbindObjectValue` that tombstones or removes the entry and decrements `readerCount`. Second, it runs `Propagate(r, b)`, and only if `b.Size() <= MaxBufferedReaderSize`. `NewReaderSize` uses the unexported `reset`, so it does not re-enter this hook. The same hook fixes the F3 miss where pooled `Reset(r.Body)` loses provenance.
2. `LimitedReader.R` is a field write that cannot be hooked. Record the bound input in the `binding` entry, and have `ReadAllBytes` and `CloneReaderBytes` check `*io.LimitedReader`'s `.R` identity against it, dropping on mismatch as a safe miss.
3. Add regression tests: after `Reset`, a clean constant is untainted and the owner's source count is unchanged, and `Reset(boundBody)` still taints.
