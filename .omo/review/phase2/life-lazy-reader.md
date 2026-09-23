# life-lazy-reader: HTTP lazy sources and body readers
Verdict: Two confirmed correctness defects: a production data race on repeated multipart parsing and false request-body provenance for mixed readers.
Scope covered: `internal/taint/request/{lazy,reader,http,source,owner,scope,lookup}.go`, `internal/taint/httpbridge/bridge.go`, `internal/taint/iobridge/bridge.go`, `internal/taint/store/binding.go`, related `iast/{net/http,net/url,io,bufio}/orchestrion.yml`, existing HTTP/reader tests, and source-range-limit commit `d3d62a4`.

## Findings

### life-lazy-reader-F1: Repeated multipart parsing races with form readers
- Severity: Critical
- Category: race
- Location: internal/taint/request/lazy.go:119-141
- Claim: After an initial successful `ParseMultipartForm`, an ordinary repeated call is a no-op in `net/http` but its unconditional advice calls `ManageMultipart` again. `replaceMatchingSuffix` writes already-managed strings back to the existing `Request.Form` and `Request.PostForm` slices, even when every value and its backing are unchanged. Another goroutine can safely read the already-parsed form while this repeated call runs in an uninstrumented application; with IAST woven in, those reads race against the added writes. The `ParseForm` and `ParseMultipartForm` advice also assign populated request map fields unconditionally, creating another opportunity for races on repeated calls.
- Evidence: `.omo/review/evidence/life-lazy-reader/zz_life_lazy_reader_race_test.go` and `.omo/review/evidence/life-lazy-reader/repeated-multipart-race.out.txt`. From the private copy run `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -race -timeout 10m -count=1 -run "TestReview(RepeatedMultipartParseDoesNotWriteForm|MultiReaderDoesNotTaintCleanPrefix)$" -v ./iast/net/http ./iast/io`. The detector reports `WARNING: DATA RACE`, the concurrent read at reproducer line 47 and the write from `replaceMatchingSuffix` at `lazy.go:141` via `net/http.(*Request).ParseMultipartForm.func1`, followed by `race detected during execution of test`.
- Fix: Record whether the form was already parsed on entry to each woven parse method and skip lazy management on no-op repeated calls. Avoid assignments of unchanged map headers and avoid copying identical managed strings into existing slices. Keep the original parse and body-read sequence untouched.

### life-lazy-reader-F2: Mixed MultiReader marks trusted bytes as request body
- Severity: High
- Category: provenance
- Location: internal/taint/request/reader.go:27-45
- Claim: The `io.MultiReader` advice binds the composite reader to an owner if *any* of its first eight inputs is bound. `ReadAllBytes` then adopts the *whole* composite result for that owner (`reader.go:67-88,119-127`). A clean reader followed by an HTTP-bound reader produces one request-body range covering both the trusted prefix and the untrusted suffix. This can falsely report a vulnerability on clean data, and the stored source value incorrectly claims the clean bytes came from the request.
- Evidence: `.omo/review/evidence/life-lazy-reader/zz_life_lazy_reader_provenance_test.go` and `.omo/review/evidence/life-lazy-reader/multireader-clean-prefix.out.txt`. Use the same woven test command above. The output shows `range [0,16) origin=http.request.body source="trusted-attacker"` and `trusted prefix attributed to request body: [0,16)`; `trusted-` came only from the unbound reader.
- Fix: For composite readers, preserve per-child byte offsets and owner attribution if feasible within the fixed budgets; otherwise do not bind a composite when any contributing reader is unbound or owner sets differ. Do not assign full-result body provenance merely because one child has a binding.

## Checked and found correct
- The focused existing woven tests passed under Go 1.26.6 and `-race`: `TestReadAllThroughSupportedWrappers`, `TestReadAllEOFWithData`, `TestReadAllBodySizeBound`, `TestMultiReaderInspectionBoundAndCleanup`, `TestMultipartValueSourcesAreIdempotent`, `TestMultipartFallbackUsesReturnedMapPosition`, and `TestServerProtocolsReleasePerRequest`. Command: `GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -race -timeout 5m -count=1 -run "^(Test(ReadAllThroughSupportedWrappers|ReadAllEOFWithData|ReadAllBodySizeBound|MultiReaderInspectionBoundAndCleanup|MultipartValueSourcesAreIdempotent|MultipartFallbackUsesReturnedMapPosition|ServerProtocolsReleasePerRequest))$" ./iast/io ./iast/net/http`.
- `EagerHTTP` does not parse forms or consume body data; `io.ReadAll` advice runs after the original operation and does not alter its bytes, error, or read count (confirmed by the focused reader tests).
- Lazy map/header prechecks bound the number of visited names and values; `ManageString` deduplicates by exact `(origin, name, value)` tuple. The configured range limit introduced in `d3d62a4` applies to newly adopted source roots; the duplicate-body branch builds exactly one range, so its default-limit constant does not exceed a lower configured count.
- The source table and request owner release are bounded and generation-validated; repeated multipart calls in the existing serial test do not grow the source count.

## Not covered / open questions
- No HTTP sink report was needed to establish F2's wrong provenance; the exact taint range and source were inspected at `io.ReadAll`.
- No full-repository suite or alternate Go version was run; focused woven tests used Go 1.26.6 with the race detector.
