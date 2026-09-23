# sink-payload-model: event payload model and size-limit review
Verdict: No correctness defect found in the reviewed model codecs or 25,000-byte payload limiting path.
Scope covered: `internal/model/{event,vulnerability,evidence,source,location,truncatedside}.go`; `internal/model/constants/{origin,vulnerabilitytype}.go`; `internal/model/truncation/truncation.go`; generated MessagePack codecs for the reviewed models; `internal/spans/{payload,orchestrion,constants}.go`; their focused tests; and the tracer's `Span.SetMetaStruct` contract.

## Findings

No findings.

## Checked and found correct

- Both wire paths use the model's declared field names and string enum shims: JSON is produced by `json.Marshal(event)`, while the MessagePack path uses the generated `Event.MarshalMsg`. `TestEventMarshalMsg`, `TestEventMarshalMsgRoundTrip`, and the enum round-trip tests cover the full event shape, including sources, redaction fields, truncation, source indexes, secure marks, and locations.
- `Finished` sends the `model.Event` itself to `Span.SetMetaStruct`, whose tracer contract accepts a `msgp.Marshaler`; therefore the MessagePack measurement and the agent serialization use the same generated marshaler. When meta-struct is unavailable, `_dd.iast.json` receives the already measured JSON bytes verbatim.
- `BuildLimitedPayload` measures the selected final representation before accepting it, then re-encodes every fallback stage. It never slices encoded bytes, so it cannot create malformed JSON or MessagePack. The fallback removes sources and substitutes `MAX_SIZE_EXCEEDED`, then progressively removes optional location strings and stack IDs while retaining vulnerability type/hash and location span ID/line.
- Dynamic driver validation under Go 1.26.6 decoded every JSON and MessagePack output and observed: normal payloads at 69 MessagePack / 87 JSON bytes; oversized payload fallbacks at 116 / 147 bytes; and the 64-vulnerability maximum fallback at 5,396 / 7,097 bytes. Every result was valid and at or below 25,000 bytes.
- `go generate ./internal/model/...` completed with no generated-code diff in the isolated copy. Focused validation passed: `go test -count=1 -timeout 15m ./internal/model/... ./internal/spans` and `go vet ./internal/model/... ./internal/spans`.
- `Event.CanAddVulnerability` and `BuildLimitedPayload` independently enforce the hard 64-vulnerability bound. The latter rejects externally constructed oversized events before encoding.
- `truncation.String` preserves valid UTF-8 rune boundaries and clones only a retained prefix; its boundary and multibyte tests pass.

## Not covered / open questions

- A live backend fixture for agent ingestion of `meta_struct` and `_dd.iast.json` was not available in this isolated review. This is the pre-existing compatibility caveat recorded in `phase1/01-design-intent.md`, not a defect demonstrated by this review.
- The review did not run the full repository, woven Orchestrion suite, or an agent process; the focused model/span tests, codec regeneration, vet check, and direct payload driver cover this component's local behavior.
