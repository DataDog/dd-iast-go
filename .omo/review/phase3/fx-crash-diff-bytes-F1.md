# fx-crash-diff-bytes-F1: strings.Builder unanchored view -> stale taint after GC address reuse

## Verdict per finding
- **crash-diff-bytes-F1**: CONFIRMED. Adjusted severity: **High** (unchanged).
- **store-writer-F2**: CONFIRMED. Adjusted severity: **High** (unchanged). This is a duplicate of crash-diff-bytes-F1 with the same root cause (see Root cause).

Both claims hold at HEAD 2e23b46. My independent woven end-to-end reproducer sends a query parameter through an ordinary handler. The clean, fully server-side SQL string `SELECT name FROM users WHERE id = 42` then produces a real **SQL_INJECTION report attributed to the HTTP parameter `id`**. The stale taint appeared on every backing-address reuse (88/88, 163/163, 1/1, 1/1) and never without one (`staleWithoutReuse=0`). A control that uses the woven `Reset()` saw address reuse but produced 0 stale taint and 0 reports. The proposed anchor fix removes the effect.

## Reproduction
Private copy `/tmp/ddiast-review/wt/fx-crash-diff-bytes-F1` (now removed), Go 1.26.6, pinned orchestrion, woven build of the nested module `iast/integration/testapp`. The real `database/sql` sink and the existing `requestEvent`/`openDB` harness from `e2e_test.go` were used.

Files (evidence dir `.omo/review/evidence/fx-crash-diff-bytes-F1/`):
- `iast__integration__testapp__zz_review_builder_aba.go` is the root-package helper, which is woven. `RowWriter{SB strings.Builder}` provides `WriteRow` (direct `WriteString`), `ZeroReset` (`*w = RowWriter{}`), `WovenReset` (`w.SB.Reset()`), `FormatRow` (`fmt.Fprintf(&w.SB, "%s", s)`), and `Row` (direct `String()`).
- `iast__integration__testapp__zz_review_builder_aba_test.go` holds the handler logic. `id := r.URL.Query().Get("id")` (36-byte UUID) is written into the builder. The holder is then reset and refilled with a clean 36-byte query, and `db.ExecContext(ctx, w.Row())` runs if `Row()` is tainted. There are three modes: GC before every row, one GC followed by collecting rows into a slice (a common handler pattern that walks the allocator back to freed slots), and a woven-`Reset` control.

Command:
```
cd iast/integration/testapp && GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 /usr/bin/time -l \
  go tool orchestrion go test -count=3 -v -timeout 15m -run TestReviewBuilderABAFalseSQLi .
```
Key output (`repro-woven-http-sql-go1.26.6.txt`, EXIT=1):
```
attempt 125: clean query "SELECT name FROM users WHERE id = 42" carries range start=0 len=36 source=http.request.parameter:id value="b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
mode=zero-value-reset/gc-each-row attempts=2000 backingAddressReused=88 staleTaintedClean=88 staleWithoutReuse=0 SQLiReports=1
REPORTED SQL_INJECTION evidence=...ValueParts:[{... Pattern:************************************ Redacted:true ...}]
REPORTED source={Origin:http.request.parameter Name:id ... Redacted:true}
mode=zero-value-reset/collect-rows attempts=2000 backingAddressReused=1 staleTaintedClean=1 staleWithoutReuse=0 SQLiReports=1   (runs 2 and 3)
mode=zero-value-reset/gc-each-row  attempts=2000 backingAddressReused=163 staleTaintedClean=163 ... SQLiReports=1              (run 3)
mode=control-woven-Reset/collect-rows attempts=2000 backingAddressReused=1 staleTaintedClean=0 SQLiReports=0                  (all runs)
```
Outcome by run: run 1 had reuse only in gc-each-row, run 2 only in collect-rows, run 3 in both. Five of 6 zero-value subtests failed, and the one that passed saw no reuse. An earlier version with 200 GC-each-row attempts saw 0 reuses and 0 false positives (`repro-first-run-gc-each-row-200-go1.26.6.txt`), so the trigger depends on the allocator and is probabilistic. When reuse does happen, the false positive is deterministic. The woven build peaked at about 359 MiB RSS, well under 4 GB.

After fix (`anchor-fix.diff`, `repro-after-anchor-fix-go1.26.6.txt`, `-count=3`): all zero-value modes showed `backingAddressReused=0 staleTaintedClean=0 SQLiReports=0`, because the anchor keeps the old backing alive, and the tests passed with EXIT=0. The plain unit tests in `iast/propagation`, `internal/taint/store`, and `internal/taint/propagation` also pass with the fix (`fix-plain-unit-tests-go1.26.6.txt`).

I did not re-run the finders' reproducers. Their captured outputs, `evidence/crash-diff-bytes/repro-builder-stale-woven-go1.26.6.txt` and `evidence/store-writer/builder-aba.out.txt`, match my observation exactly (a clean value tainted with the stale source only on address reuse). The `run1..run4*` files and `iast__internal__zzfx__builder_aba_test.go` in this evidence dir (timestamped 16:33) come from an earlier attempt of this node, and I did not rely on them.

## Reachability
- **Surface**: this is ordinary customer code with default configuration. `DD_IAST_ENABLED` defaults to `true`, sampling is 30%, and the request only has to be sampled. Every step is idiomatic. A direct `WriteString` of request data is followed by a zero-value reinitialisation of a holder struct (`*w = T{}` or `b = strings.Builder{}`), which is not a hooked op. The same holder is then refilled through `io.Writer` (`fmt.Fprintf`, `io.WriteString`, `text/template`, or any dependency), and finally `String()` is called directly. A `Reset` through a method value or in a non-root dependency also leaves the entry alive, as the finder's method-value probe shows.
- **Preconditions**: all of the following happen in one sampled request. The same `strings.Builder` storage is reused. At the next woven op, the refill has **exactly the same len and cap** as the last tracked view. A GC cycle completes in between, and the allocator returns the freed slot. Equal len and cap is natural for fixed-width data such as UUIDs, IDs, timestamps, and fixed templates. The per-request probability is low, but at production request volume it is not negligible, and each hit produces a confident false SQLi or CMDi report that names a real attacker-controlled source.
- **Not a documented limitation**: README "Propagation coverage" says that indirect calls *do not propagate* taint (a miss) and that *Builder value copies* are unsupported. Stale ranges are documented only for *mutable byte aliases*. Nothing documents that a Builder reset or refill outside hooks can *create* false taint. The design (phase1 00-architecture section 4) says missed writer updates are handled by alias invalidation and a dirty bit. That holds for `bytes.Buffer` (Anchor plus native hooks) but not for `strings.Builder`. Rule 4 ("no false taint") is broken.

## Adjusted severity
**High** for both findings. This is a false-positive SQLi/CMDi on a supported path (direct Builder writes plus `String`), caused by stale taint on reused memory, which the brief lists under High. It is not Critical because it needs a narrow allocator coincidence and cannot crash, leak, or change host behavior. Both findings share one root cause and should be tracked as one issue.

## Root cause (file:line @2e23b46)
- `iast/propagation/writer.go:202-205`: `builderView` returns `writerView(stringPointer(value), Len, Cap)` with no `Anchor` or `Backing`, unlike `bufferView` at 207-216.
- `internal/taint/store/writer.go:23-27` documents "Buffer views also retain an Anchor ...; builders do not." The entry keeps only `object` (the Builder struct), not its backing array.
- `internal/taint/store/writer.go:257` (`record.writers[index].view != view`) and `:448-451` (`writerViewIndexLocked`) validate by numeric `(Pointer, Length, Capacity)` equality only. After the old array is freed and its address reused with equal len and cap, the match succeeds.
- `internal/taint/propagation/writer.go:215-237`: `publishWriterString` clones the clean result and `AdoptString`s the stale set onto it.
- `strings.Builder` has no native invalidation hook (orchestrion.yml has hooks only for Buffer, 1553-1680), so unhooked resets and refills are never observed.

## Minimal fix
Anchor builder views the way Buffer views are anchored (verified in the private copy, see `anchor-fix.diff`):
```go
func builderView(builder *strings.Builder) store.WriterView {
	value := builder.String()
	view := writerView(stringPointer(value), builder.Len(), builder.Cap())
	if builder.Cap() > 0 {
		if anchor := unsafe.StringData(value); anchor != nil { // empty-string StringData is unspecified
			view.Anchor = anchor
			view.Backing = uintptr(unsafe.Pointer(anchor))
		}
	}
	return view
}
```
`validWriterView` (store/writer.go:402-405) already accepts `Backing != 0 && Anchor != nil`. The interval index (`refreshWriterIndexLocked`, :440) stays Buffer-only, and view equality now includes the anchor. The retained backing is already charged as `sizeClass(cap)`, is bounded to at most 8 writers per owner at 64 KiB or less each, and is released on `Reset` or owner finish, so this adds no unbounded retention. Add the woven reproducer above, or its store-level equivalent, as a regression test.
