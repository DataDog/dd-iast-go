# sink-evidence: evidence collection and value parts
Verdict: One High-severity owner-provenance defect in joined command evidence; the reviewed bounds, ordering, deduplication, and accessors otherwise behaved as specified.
Scope covered: `internal/taint/evidence/{evidence.go,evidence_test.go,collection_behavior_test.go,accessors_test.go,fuzz_test.go}`; request visitor/store snapshot, command sink, report span selection, redaction analyzers and part builder, model truncation and constructors; isolated Go package tests and a five-owner report reproducer.

## Findings
### sink-evidence-F1: Joined evidence omits a contributing owner's bound span
- Severity: High
- Category: provenance
- Location: internal/taint/evidence/evidence.go:339,404-413
- Claim: `CollectJoinedStrings` visits up to 256 arguments, each potentially from a distinct active request. `canonicalize` admits all their unsafe ranges but `addOwner` silently retains only four owner identities. If the only bound request span belongs to a fifth contributing argument and the sink context has no span, `selectTaintedAnnotation` (`internal/vulnerability/tainted.go:116`) cannot find that owner and creates an orphan report. The event is attached to the wrong trace despite complete live source provenance.
- Evidence: `.omo/review/evidence/sink-evidence/zz_review_owner_fanout_test.go` and `.omo/review/evidence/sink-evidence/owner_fanout.out.txt`; from the private copy run `GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4 go test -run '^TestJoinedEvidenceFindsFifthBoundOwner$' -count=1 -timeout=5m -v ./internal/vulnerability`. Captured failure: `fifth owner reports = 0, snapshot owners = 4, orphan spans = 1; want 1 report on fifth owner`.
- Fix: Define a joined-collection owner bound separately from the store's per-value four-owner snapshot limit. Preserve all contributing owner identities up to that bound (256 arguments), or fail collection explicitly rather than silently omitting identities; then select the bound span from the complete set.

## Checked and found correct
- `matchesJoin` checks each argument/separator against the supplied result before adding offsets; all offsets stay within the <=64 KiB result. Existing early/late argument and mismatch tests passed.
- Source indexing hashes and compares full `(origin, name, value)` tuples before cloning; repeated identities share one index. `reindexSources` orders retained sources by first output occurrence and recomputes retained source bytes after losing overlapping intervals.
- Collection validates zero-length and out-of-bounds ranges before indexing and drops the whole snapshot at 256 ranges or 256 KiB copied source names/values. `PartValue` rejects nil, zero length, out-of-bounds, and overflowed lengths; existing bounds tests passed.
- Canonical sorting resolves overlapping ranges deterministically and fills clean gaps with value parts. Existing reversal and fuzz-seed tests passed; part count stays within 513.
- Model truncation counts Unicode characters and clones a prefix at a rune boundary; the redaction part builder shares a 250-character budget for visible value parts. SQL and command analysis enforce the 32 KiB input cap and use fully sensitive redaction for oversized analyses. The isolated `go test -count=1 -timeout=10m ./internal/taint/evidence ./internal/taint/redaction ./internal/model/...` run passed.

## Not covered / open questions
- No woven `os/exec` end-to-end test or broad fuzz/race run; the failing reproducer exercises real request scopes, taint collection, span bindings, redaction, and the reporting entry point without weaving.
- The fifth-owner failure was observed when the first four owners had no bound span. Behavior when multiple contributing owners have bound spans remains a policy question, but does not affect this finding.
