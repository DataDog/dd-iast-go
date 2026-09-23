# sink-parity: IAST report wire parity
Verdict: One High schema incompatibility in truncated tainted SQL evidence; origin/type names and ordinary evidence layout match the shared contract, but normal Go meta-struct reports escape the system-tests schema check.
Scope covered: `internal/model/{constants/origin.go,constants/vulnerabilitytype.go,event.go,vulnerability.go,evidence.go,source.go,location.go}`, `internal/taint/{evidence/evidence.go,redaction/source.go,redaction/sql.go,redaction/command.go}`, `internal/vulnerability/{tainted.go,report.go,dedup/dedup.go,stacktrace/stacktrace.go}`, `internal/spans/{tainted.go,payload.go,orchestrion.go}`, `internal/taint/request/scope.go`, `internal/config/config.go`; Java `SourceTypes`, `VulnerabilityTypes`, `VulnerabilityType`, `Location`, `EvidenceAdapter`; JS IAST source types, formatter, reporter; Python IAST constants/reporter; `system-tests/tests/appsec/iast` schema, schema test, sampling test, SQL/command sink and parameter-source tests.

## Findings

### sink-parity-F1: Truncation removes a required value from tainted evidence
- Severity: High
- Category: redaction
- Location: internal/taint/redaction/source.go:188-208
- Claim: Once an unredacted literal fills the configured evidence character budget, a following tainted part is emitted with `SourceIndex`, `Truncated: right`, and an empty `Value`. The `json:"value,omitempty"` tag in `internal/model/evidence.go:56-63` and equivalent omission in `internal/model/evidence_gen.go:168-174` remove that field. `system-tests/tests/appsec/iast/vulnerability_schema.json` requires both `value` and `source` for an unredacted tainted part; the resulting report cannot satisfy the shared schema. This is reachable with the default budget of 250 and a SQL query whose tainted identifier starts immediately after a 250-character prefix. `redaction.BuildWithSensitive` is the actual `ReportTainted` conversion path, not just an isolated model constructor.
- Evidence: `.omo/review/evidence/sink-parity/schema_parity_test.go` (copy into `internal/taint/redaction/schema_parity_test.go` in the private review copy); run `GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go test -timeout 5m -run '^TestTaintedPartAtTruncationBoundaryHasRequiredValue$' -count=1 -v ./internal/taint/redaction`. Captured `.omo/review/evidence/sink-parity/schema_parity.out.txt`: `unredacted tainted part omits required value: map[source:0 truncated:"right"]`; serialized part `{"truncated":"right","source":0}`. The test fails with exit status 1 as expected.
- Fix: At the truncation boundary, do not emit a zero-length unredacted tainted part. Mark the last retained part truncated, or make the serialized truncated tainted part include its required `value` field; verify both JSON and MessagePack against the shared schema.

### sink-parity-F2: Schema test skips the normal Go meta-struct payload
- Severity: Medium
- Category: test-gap
- Location: system-tests/tests/appsec/iast/test_vulnerability_schema.py:13-21
- Claim: The schema test reads only `span["meta"]["_dd.iast.json"]` and skips every span without that tag. Go's normal span finish writes `meta_struct["iast"]` first (`internal/spans/orchestrion.go:44-54`) and emits JSON only when `SetMetaStruct` fails. Other system-tests helpers already read both. Thus the normal Go report path is not schema-checked, concealing F1 from that test.
- Evidence: static reasoning only (NEEDS-REPRO): compare the schema test's `_dd.iast.json` guard with Go's `SetMetaStruct` branch and `system-tests/tests/appsec/iast/utils.py:13-25`.
- Fix: Reuse the shared `get_iast_event` logic or validate `meta_struct["iast"]` as well as the JSON tag.

## Checked and found correct
- The Go origin strings (`internal/model/constants/origin.go:96-137`) and vulnerability type strings (`internal/model/constants/vulnerabilitytype.go:171-242`) agree with the system-tests schema for the implemented SQL and command sinks, and with the corresponding Java, JS and Python constants. Extra declared origins or vulnerability types are not findings when their integrations are intentionally unsupported.
- The normal tainted report has `sources`, `vulnerabilities`, zero-based `valueParts[].source`, optional `secure_marks`, `pattern` plus `redacted: true` for scrubbed parts, and `location.spanId`; these agree with the schema and the Java/JS formatter patterns. The reproduced boundary case is the exception.
- Go uses FNV-1a over type and location for sink hashes (`internal/model/vulnerability.go:26-44`), whereas Java and Python use CRC32. The shared schema specifies an integer unique identifier, not a common cross-runtime algorithm; the default per-request cap, process dedup capacity and one-hour window are bounded in Go. This algorithm difference alone is not a compatibility defect.
- Go redacts source-sensitive content and sink-sensitive intervals before committing the event (`internal/taint/redaction/source.go:40-90,99-113,185-218`), and remaps source indexes transactionally (`internal/spans/tainted.go:61-167`). Analysis failures use a fully-sensitive fallback; the documented explicit redaction-disabled setting is the exception.
- `system-tests/tests/appsec/iast/test_sampling_by_route_method_count.py` expects route/method coverage across 30 requests, whereas Go explicitly implements random per-request 30% sampling with a two-vulnerability default cap (`internal/taint/request/scope.go:147-159`, `internal/config/config.go:73-75`). This is a feature/capability mismatch, not evidence that a Go-enabled system-test run has failed.

## Not covered / open questions
- No live backend fixture, full system-tests weblog or cross-language integration suite was run; the focused reproducer exercises source collection, SQL analysis, redaction and JSON event encoding in the isolated Go copy. Whether the backend rejects the schema-invalid meta-struct payload needs its own integration confirmation.
- This review did not reproduce the documented unsupported taint paths, benchmark overhead, or test service-name hashing for vulnerability types not emitted by the supported SQL/command integrations.
