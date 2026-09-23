# hooks-yml-bytes: byte call-site propagation and aliases
Verdict: No correctness findings in the reviewed bytes join points and advice.
Scope covered: `iast/propagation/orchestrion.yml` bytes function-call aspects and byte-slice aspect; `iast/propagation/bytes.go` all 28 wrappers; `internal/taint/propagation/{propagation,bytes_exact}.go` window derivation, copy, join, repeat, replace, case and UTF-8 transforms; relevant Go 1.26.6 and Go 1.27.0 `bytes` implementation; `iast/internal/propagationtest/bytes.go` and existing byte propagation tests.

## Findings
None.

## Checked and found correct
- The 28 `bytes.*` function-call aspects each target their corresponding wrapper, and wrappers invoke the original operation once before provenance work. Window outputs are returned unchanged; `ByteWindow`/`ByteWindows` derive alias keys instead of cloning or adopting a new allocation. `Cut` derives both returned slices; `Split*` and `Fields*` derive the bounded result prefix.
- The byte outputs of `TrimSpace`, `Fields`, `Split` and `Cut` still alias the input at the expected offset and propagate taint in a woven Go 1.26.6 test. Writing to each returned view changed the original slice; a named `[]byte` argument compiled and preserved the same alias and provenance. A clean byte input remained clean. The private test and its named-type fixture are in `.omo/review/evidence/hooks-yml-bytes/zz_review_bytes_test.go` and `named-fixture.patch`.
- The focused woven test command in `.omo/review/evidence/hooks-yml-bytes/woven-byte-tests.txt` exited 0. Existing byte tests also passed for partial window ranges, copy/join/repeat/replace, case conversion, UTF-8 replacement, and bounded coarse provenance.
- Go 1.26.6 `bytes.Join`, `Repeat`, `Replace`, `Map`, case transforms and `ToValidUTF8` create independent output storage on the paths that the advice adopts. The observed `Trim*`, `Fields*`, `Split*` and `Cut*` outputs preserve their input backing rather than being replaced by IAST copies.

## Not covered / open questions
- Executable checks were limited to the focused byte suite under Go 1.26.6; the full repository suite, fuzzing and woven Go 1.27.0 run were not performed. Go 1.27.0 source was compared for byte allocation behavior.
- The documented lack of hooks for arbitrary `append`, `copy` and direct byte writes is not a finding against these named `bytes` wrappers; stale taint after such a write remains the documented mutable-byte limitation.
