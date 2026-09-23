# light-model: Model event bounds and MessagePack codecs
Verdict: The model changes and generated codecs are correct; one new round-trip fixture contains an invalid source reference.
Scope covered: `internal/model/event.go`, `event_test.go`, `event_gen.go`, model source/evidence/vulnerability/location codecs, `internal/model/constants/{origin,vulnerabilitytype}.go`, their generated codecs and round-trip tests, and the vulnerability-limit configuration.

## Findings
### light-model-F1: Round-trip fixture references a nonexistent source
- Severity: Low
- Category: test-gap
- Location: internal/model/event_test.go:88,115
- Claim: `TestEventMarshalMsgRoundTrip` creates one `Event.Sources` entry but sets its `ValuePart.SourceIndex` to 3. The codec round-trip only proves that this invalid integer survives serialization; it does not model a valid event source reference.
- Evidence: Static review of the fixture; `internal/model/event_test.go:88` initializes the index to 3 and the event has one source at lines 90-98. The `SourceIndex` field receives that index at line 115.
- Fix: Set `sourceIndex` to 0 so the fixture's value part references the sole source.

## Checked and found correct
- `MaxVulnerabilities` aliases the configuration's hard bound of 64. `NewEvent` caps its initial capacity, and `AddVulnerability` applies the minimum of the configured and hard limits before appending; deduplication behavior remains in the same admission path.
- The generated MessagePack codecs are synchronized with their source definitions: `GOTOOLCHAIN=go1.26.6 go generate ./internal/model/...` in the private worktree produced no generated-file differences.
- Model tests cover populated event round trips with trailing bytes and reuse, unknown fields, malformed payloads, enum values and errors, plus the event hard cap. `GOTOOLCHAIN=go1.26.6 go test -timeout 15m ./internal/model/...` passed.

## Not covered / open questions
- No full-repository or instrumented test run was needed for this model-only review.
