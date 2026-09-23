# crash-unsafe: unsafe, uintptr, and weak-pointer memory safety
Verdict: One confirmed High lifecycle/provenance defect exists in the weak span-annotation map; all audited unsafe and uintptr conversions are one-way numeric comparisons with typed lifetime anchors and no observed pointer reconstruction.

Scope covered: production `unsafe`, `uintptr`, and `weak.Pointer` uses found in `iast/propagation/{writer.go,coarse.go,orchestrion.yml}`, `internal/taint/{jsonbridge/bridge.go,propagation/{json.go,propagation.go},request/lazy.go,store/{store.go,root.go,value.go,lookup.go,binding.go,writer.go,mutation.go,owner.go,limits.go}}`, `internal/spans/{annotation.go,orchestrion.go,owner.go,vulnerability.go,tainted.go}`, and `internal/taint/writerbridge/bridge.go`; scoped checkptr, race, and woven checkptr suites were run in the private copy.

## Findings

### crash-unsafe-F1: A live child recreates an open annotation after its root finishes
- Severity: High
- Category: provenance
- Location: `internal/spans/annotation.go:119-149`, `internal/spans/annotation.go:184-211`, `internal/spans/orchestrion.go:27-36`
- Claim: `Finished(root)` deletes and closes the root-keyed annotation before the tracer finishes the root. A still-live child retains that root relationship; `AnnotationFor(child)` or `BindScope(child)` can then insert a new sampled, open annotation under the already-finished root key. The root has no second finish hook to submit or remove that replacement. A later `Finished(child)` uses the child key, leaving the replacement associated with the finished root. Any finding committed to it is therefore not emitted at root finish; the retained annotation can also hold source identities beyond the root lifecycle. This is a supported root/child lifecycle, not GC address reuse.
- Evidence: `.omo/review/evidence/crash-unsafe/finished_root_repro_test.go` and `.omo/review/evidence/crash-unsafe/finished_root_repro.out.txt`; exact command: `env GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 GOCACHE=/tmp/ddiast-review/wt/crash-unsafe/.gocache GOTMPDIR=/tmp/ddiast-review/wt/crash-unsafe/.gotmp go test -count=1 -v -run TestReproFinishedRootAcceptsReplacementFromLiveChild -timeout=5m ./internal/spans`. Captured failure: `live child recreated an open annotation for an already-finished root`; after child finish, `root-key replacement retained=true closed=false`.
- Fix: Make annotation admission trace-lifecycle-aware: reject creation once the root is finished, and use a cleanup hook keyed to an immutable trace/lifecycle generation rather than a pooled `*tracer.Span` allocation. The eventual removal must occur at trace completion and must not let a new logical pooled span inherit a closed marker.

### crash-unsafe-F2: Annotation capacity admission is not an atomic reservation
- Severity: Medium
- Category: memory-bound
- Location: `internal/spans/annotation.go:126-145`, `internal/spans/annotation.go:190-207`, `internal/spans/annotation.go:223-236`, `internal/spans/vulnerability.go:21-31`
- Claim: `trimStore` tests `store.Size()` before the distinct-key `LoadOrCompute` insertion. Concurrent callers can each observe free capacity and later insert different root keys; the check does not reserve a slot. The map is safe for concurrent access, but this admission sequence does not itself establish the configured `MaxConcurrentRequests` as a hard bound. I did not assign High because a deterministic interleaving reproducer requires an insertion barrier that production code does not expose.
- Evidence: static reasoning only (NEEDS-REPRO)
- Fix: Reserve capacity atomically as part of actual new-key admission (and release it on `Finished` and dead-key cleanup), rather than checking size before insertion. Preserve the non-blocking/drop-on-contention policy.

## Checked and found correct

- **No production `uintptr` is converted back to a pointer.** The global non-test inventory found only pointer-to-`uintptr` conversions, `reflect.Value.Pointer`, numeric hashing/comparison, and bounded subtraction. The keys are never dereferenced or reconstructed with `unsafe.Pointer`.
- **Store identity keys have typed liveness anchors and generations.** `StringKey`/`BytesKey` are unanchored query metadata only; stored roots retain `stringAnchor` or `bytesAnchor`. `bindingTable` retains the bound object in an `any`. Owner/root generation checks in `lookup.go` prevent a finished or superseded root from contributing after reuse. The documented complete-allocation-base precondition for adoption is honored by audited production callers.
- **Writer pointer arithmetic is non-dereferencing and bounded by the writer view.** `writer.go` derives a bytes.Buffer backing comparison key from a live slice and keeps an interior typed `Anchor`; tracked buffer records retain their receiver object. `writerbridge` stores only short-lived receiver/backing numbers. The injected `bytes.Buffer` advice has the same one-way numeric pattern.
- **JSON bridge arithmetic is guarded.** `bytesAlias` proves a literal lies within the document before `internal/taint/propagation/json.go` computes its offset; clone slicing validates offset and length before use. `jsonbridge` numeric document/token addresses are compared only. The suspected stack-relocation issue was disproved for the woven `encoding/json.Unmarshal` state: the minimal Orchestrion build reports `encoding/json/decode.go:106: moved to heap: d` in `.omo/review/evidence/crash-unsafe/json_escape_probe.out.txt`.
- **Weak pointers are made from heap `*tracer.Span` objects, not stack objects or interior byte/string pointers.** `weak.Pointer.Value` results are rechecked through exact owner ID/generation and annotation closure checks before use. The confirmed finding is a lifecycle/admission issue, not a weak-pointer use-after-free or post-GC address alias.
- **Runtime validation:** scoped `-gcflags=all=-d=checkptr` and `-race` suites passed; the woven `iast/propagation` checkptr suite passed. Outputs are in `checkptr.out.txt`, `race.out.txt`, and `woven-checkptr.out.txt`.

## Not covered / open questions

- `go test -asan` could not run on this host because Go 1.26.6 reports `-asan is not supported on darwin/arm64`; see `.omo/review/evidence/crash-unsafe/asan.out.txt`.
- F2 needs a deterministic contention test or an admission test seam before increasing its severity. The static TOCTOU argument is not a demonstrated overshoot.
- I did not reproduce logical-span reuse from the tracer's optional span pool. F1 is independently proven without pooling; a pool reuse case could increase its cross-request impact.
