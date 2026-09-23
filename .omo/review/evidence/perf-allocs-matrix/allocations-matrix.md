# Allocation matrix: plain vs woven (go test -benchmem -benchtime=2000x -count=1)

*ns/op is indicative only: the machine is shared, and root-module packages ran in parallel (GOFLAGS=-p=4).

| module | benchmark | allocs/op plain | allocs/op woven | B/op plain | B/op woven | ns/op plain* | ns/op woven* |
|---|---|---:|---:|---:|---:|---:|---:|
| root | BenchmarkAnalyzeCommand | 2 | 2 | 72 | 72 | 103.6 | 62.7 |
| root | BenchmarkAnalyzeSQL/q_quote_flood | 8 | 8 | 5568 | 5568 | 62787.0 | 35472.0 |
| root | BenchmarkAnalyzeSQL/two_hundred_literals | 26 | 26 | 34709 | 34709 | 141729.0 | 69487.0 |
| root | BenchmarkAnalyzeSQL/typical | 21 | 21 | 1680 | 1682 | 7861.0 | 3174.0 |
| root | BenchmarkCanonicalizeTwo | 0 | 0 | 0 | 0 | 915.2 | 504.4 |
| root | BenchmarkCollectStringMiss | 0 | 0 | 0 | 0 | 31.6 | 14.2 |
| root | BenchmarkConcatFreshGoroutine | 3 | 3 | 152 | 152 | 1782.0 | 915.6 |
| root | BenchmarkConcatTwo | 0 | 0 | 0 | 0 | 105.3 | 56.2 |
| root | BenchmarkFinishWithActiveWriter | 6 | 6 | 225 | 224 | 2094.0 | 1136.0 |
| root | BenchmarkHasValuesClean | 0 | 0 | 0 | 0 | 3.6 | 2.0 |
| root | BenchmarkLiteralActiveClean | 0 | 0 | 0 | 0 | 81.0 | 18.9 |
| root | BenchmarkLiteralInactive | 0 | 0 | 0 | 0 | 29.7 | 21.4 |
| root | BenchmarkMappedPattern | 0 | 0 | 0 | 0 | 32.0 | 16.4 |
| root | BenchmarkOperatorConcat4ActiveClean | 1 | 1 | 26 | 24 | 58.8 | 25.2 |
| root | BenchmarkOperatorConcat4Inactive | 1 | 1 | 24 | 24 | 72.3 | 51.5 |
| root | BenchmarkOperatorConversionsInactive | 1 | 1 | 24 | 24 | 17.3 | 11.6 |
| root | BenchmarkOperatorOptimizedConversionExcluded | 0 | 0 | 0 | 0 | 3.7 | 2.0 |
| root | BenchmarkOperatorSlicesInactive | 0 | 0 | 0 | 0 | 5.1 | 4.3 |
| root | BenchmarkReportActiveClean | 0 | 0 | 0 | 0 | 23.4 | 14.4 |
| root | BenchmarkReportInactive | 0 | 0 | 0 | 0 | 6.0 | 2.0 |
| root | BenchmarkSliceTwo | 0 | 0 | 0 | 0 | 108.1 | 59.6 |
| root | BenchmarkStringLookup/hit | 0 | 0 | 0 | 0 | 722.1 | 370.5 |
| root | BenchmarkStringLookup/miss | 0 | 0 | 0 | 0 | 29.1 | 7.2 |
| root | BenchmarkStringLookup/no-active | 0 | 0 | 0 | 0 | 4.2 | 2.0 |
| root | BenchmarkStringLookup/visit | 0 | 0 | 0 | 0 | 788.6 | 384.3 |
| benchmarks/overhead | BenchmarkBytesBuffer | 2 | 2 | 80 | 80 | 38.2 | 55.0 |
| benchmarks/overhead | BenchmarkBytesBufferCopies/active-unrelated | - | 0 | - | 0 | - | 149.4 |
| benchmarks/overhead | BenchmarkBytesBufferCopies/read | - | 2 | - | 56 | - | 244.2 |
| benchmarks/overhead | BenchmarkBytesBufferCopies/write | - | 2 | - | 64 | - | 1766.0 |
| benchmarks/overhead | BenchmarkBytesClone | 1 | 1 | 24 | 24 | 17.4 | 10.9 |
| benchmarks/overhead | BenchmarkBytesJoin | 1 | 1 | 16 | 16 | 40.6 | 24.1 |
| benchmarks/overhead | BenchmarkBytesMap | 1 | 1 | 16 | 16 | 43.3 | 31.0 |
| benchmarks/overhead | BenchmarkBytesRepeat | 1 | 1 | 16 | 16 | 18.8 | 15.2 |
| benchmarks/overhead | BenchmarkBytesReplaceAll | 1 | 1 | 16 | 16 | 52.4 | 41.3 |
| benchmarks/overhead | BenchmarkBytesSplit | 1 | 1 | 80 | 80 | 48.3 | 27.5 |
| benchmarks/overhead | BenchmarkBytesToLower | 1 | 1 | 16 | 16 | 23.9 | 20.9 |
| benchmarks/overhead | BenchmarkBytesTrimSpace | 0 | 0 | 0 | 0 | 3.0 | 2.4 |
| benchmarks/overhead | BenchmarkFmtSprintf | 1 | 1 | 17 | 17 | 51.8 | 62.1 |
| benchmarks/overhead | BenchmarkHTTPRoundTrip | 113 | 447 | 9793 | 39285 | 78284.0 | 78860.0 |
| benchmarks/overhead | BenchmarkHealth | 19 | 19 | 6115 | 6115 | 1754.0 | 1151.0 |
| benchmarks/overhead | BenchmarkPropagationActiveUntainted/ByteCopy | 1 | 1 | 8 | 8 | 14.0 | 13.5 |
| benchmarks/overhead | BenchmarkPropagationActiveUntainted/ByteWindow | 0 | 0 | 0 | 0 | 5.4 | 3.5 |
| benchmarks/overhead | BenchmarkPropagationActiveUntainted/StringCoarse | 1 | 1 | 8 | 8 | 42.2 | 35.1 |
| benchmarks/overhead | BenchmarkPropagationActiveUntainted/StringCopy | 1 | 1 | 8 | 8 | 9.5 | 5.4 |
| benchmarks/overhead | BenchmarkPropagationActiveUntainted/StringWindow | 0 | 0 | 0 | 0 | 5.0 | 4.1 |
| benchmarks/overhead | BenchmarkPropagationActiveUntainted/StringWindows | 1 | 1 | 48 | 48 | 41.2 | 23.9 |
| benchmarks/overhead | BenchmarkRequestProcessing | 47 | 47 | 8798 | 8801 | 3296.0 | 2545.0 |
| benchmarks/overhead | BenchmarkRequestProcessingParallel | 47 | 47 | 8820 | 8814 | 1177.0 | 975.4 |
| benchmarks/overhead | BenchmarkStrconvQuote | 1 | 1 | 16 | 16 | 94.0 | 61.1 |
| benchmarks/overhead | BenchmarkStringsBuilder | 2 | 2 | 24 | 24 | 30.8 | 25.0 |
| benchmarks/overhead | BenchmarkStringsClone | 1 | 1 | 24 | 24 | 21.0 | 8.3 |
| benchmarks/overhead | BenchmarkStringsJoin | 1 | 1 | 16 | 16 | 56.2 | 25.8 |
| benchmarks/overhead | BenchmarkStringsRepeat | 1 | 1 | 16 | 16 | 42.5 | 26.1 |
| benchmarks/overhead | BenchmarkStringsReplaceAll | 1 | 1 | 16 | 16 | 64.0 | 45.2 |
| benchmarks/overhead | BenchmarkStringsSplit | 1 | 1 | 48 | 48 | 37.9 | 28.7 |
| benchmarks/overhead | BenchmarkStringsSplitSeq | 0 | 0 | 0 | 0 | 20.1 | 15.8 |
| benchmarks/overhead | BenchmarkStringsToLower | 1 | 1 | 16 | 16 | 49.3 | 30.1 |
| benchmarks/overhead | BenchmarkStringsTrimSpace | 0 | 0 | 0 | 0 | 2.9 | 2.4 |
| benchmarks/overhead | BenchmarkURLQueryEscape | 1 | 1 | 16 | 16 | 35.7 | 23.0 |
| benchmarks/overhead | BenchmarkWeakCipherActiveSpan | 1 | 72 | 128 | 12361 | 619.6 | 4989.0 |
| benchmarks/overhead | BenchmarkWeakCipherNoActiveSpan | 1 | 5 | 128 | 256 | 615.7 | 469.5 |
| benchmarks/overhead | BenchmarkWeakHashActiveSpan | 0 | 71 | 0 | 12247 | 64.3 | 4550.0 |
| benchmarks/overhead | BenchmarkWeakHashNoActiveSpan | 0 | 4 | 0 | 128 | 120.3 | 158.7 |
| iast/database/sql/testapp | BenchmarkStmtExecContextInactive | 3 | 3 | 96 | 96 | 169.5 | 262.3 |
| iast/os/exec/testapp | BenchmarkCommandStartErrorInactive | 28 | 28 | 21034 | 21037 | 1682558.0 | 2323464.0 |
| iast/integration/testapp | BenchmarkJSONUnmarshalActiveClean | 12 | 12 | 376 | 376 | 938.9 | 1863.0 |
| iast/integration/testapp | BenchmarkJSONUnmarshalClean | 12 | 12 | 377 | 377 | 1012.0 | 1377.0 |

## Rows where allocs/op differ

- benchmarks/overhead BenchmarkHTTPRoundTrip: 113 -> 447
- benchmarks/overhead BenchmarkWeakCipherActiveSpan: 1 -> 72
- benchmarks/overhead BenchmarkWeakCipherNoActiveSpan: 1 -> 5
- benchmarks/overhead BenchmarkWeakHashActiveSpan: 0 -> 71
- benchmarks/overhead BenchmarkWeakHashNoActiveSpan: 0 -> 4

## benchmarks/overhead, same weaving toolchain: control (orchestrion + dd-trace-go) vs IAST (+ dd-iast-go), sampling=100, -count=1 -benchtime=2000x -cpu=1

| benchmark | allocs/op control | allocs/op IAST | B/op control | B/op IAST | ns/op control* | ns/op IAST* |
|---|---:|---:|---:|---:|---:|---:|
| BenchmarkBytesBuffer | 2 | 2 | 80 | 80 | 63.2 | 62.7 |
| BenchmarkBytesBufferCopies/active-unrelated | 0 | 0 | 0 | 0 | 16.9 | 530.6 |
| BenchmarkBytesBufferCopies/read | 1 | 2 | 8 | 56 | 21.6 | 653.7 |
| BenchmarkBytesBufferCopies/write | 1 | 2 | 16 | 64 | 105.7 | 4108.0 |
| BenchmarkBytesClone | 1 | 1 | 24 | 24 | 35.2 | 40.9 |
| BenchmarkBytesJoin | 1 | 1 | 16 | 16 | 75.6 | 59.6 |
| BenchmarkBytesMap | 1 | 1 | 16 | 16 | 214.7 | 4944.0 |
| BenchmarkBytesRepeat | 1 | 1 | 16 | 16 | 237.8 | 58.9 |
| BenchmarkBytesReplaceAll | 1 | 1 | 16 | 16 | 106.1 | 291.9 |
| BenchmarkBytesSplit | 1 | 1 | 80 | 80 | 90.3 | 90.5 |
| BenchmarkBytesToLower | 1 | 1 | 16 | 16 | 41.1 | 90.9 |
| BenchmarkBytesTrimSpace | 0 | 0 | 0 | 0 | 4.4 | 4.4 |
| BenchmarkFmtSprintf | 1 | 1 | 16 | 16 | 162.0 | 104.3 |
| BenchmarkHTTPRoundTrip | 414 | 510 | 33988 | 40904 | 679986.0 | 469922.0 |
| BenchmarkHealth | 19 | 19 | 6114 | 6114 | 4247.0 | 2962.0 |
| BenchmarkPropagationActiveUntainted/ByteCopy | 1 | 1 | 8 | 8 | 1460.0 | 23.2 |
| BenchmarkPropagationActiveUntainted/ByteWindow | 0 | 0 | 0 | 0 | 8.0 | 7.8 |
| BenchmarkPropagationActiveUntainted/StringCoarse | 1 | 1 | 8 | 8 | 115.6 | 71.2 |
| BenchmarkPropagationActiveUntainted/StringCopy | 1 | 1 | 8 | 8 | 301.5 | 20.3 |
| BenchmarkPropagationActiveUntainted/StringWindow | 0 | 0 | 0 | 0 | 6.6 | 30.2 |
| BenchmarkPropagationActiveUntainted/StringWindows | 1 | 1 | 48 | 48 | 145.7 | 141.2 |
| BenchmarkRequestProcessing | 47 | 47 | 8794 | 8793 | 6566.0 | 7401.0 |
| BenchmarkRequestProcessingParallel | 47 | 47 | 8792 | 8792 | 8120.0 | 10524.0 |
| BenchmarkStrconvQuote | 1 | 1 | 16 | 16 | 243.4 | 131.4 |
| BenchmarkStringsBuilder | 2 | 2 | 24 | 24 | 348.2 | 87.0 |
| BenchmarkStringsClone | 1 | 1 | 24 | 24 | 19.6 | 23.4 |
| BenchmarkStringsJoin | 1 | 1 | 16 | 16 | 117.7 | 77.8 |
| BenchmarkStringsRepeat | 1 | 1 | 16 | 16 | 11682.0 | 56.3 |
| BenchmarkStringsReplaceAll | 1 | 1 | 16 | 16 | 3079.0 | 102.9 |
| BenchmarkStringsSplit | 1 | 1 | 48 | 48 | 12086.0 | 83.2 |
| BenchmarkStringsSplitSeq | 0 | 0 | 0 | 0 | 29.6 | 60.4 |
| BenchmarkStringsToLower | 1 | 1 | 16 | 16 | 3372.0 | 77.8 |
| BenchmarkStringsTrimSpace | 0 | 0 | 0 | 0 | 4.4 | 4.8 |
| BenchmarkURLQueryEscape | 1 | 1 | 16 | 16 | 95.9 | 110.2 |
| BenchmarkWeakCipherActiveSpan | 56 | 99 | 5528 | 20034 | 5466.0 | 20612.0 |
| BenchmarkWeakCipherNoActiveSpan | 1 | 5 | 128 | 256 | 993.1 | 881.4 |
| BenchmarkWeakHashActiveSpan | 55 | 98 | 5400 | 19919 | 4564.0 | 18708.0 |
| BenchmarkWeakHashNoActiveSpan | 0 | 4 | 0 | 128 | 172.3 | 285.3 |

## Sampled-out (DD_IAST_REQUEST_SAMPLING=0) vs control, same runner

| benchmark | allocs/op control | allocs/op IAST s=0 | B/op control | B/op IAST s=0 |
|---|---:|---:|---:|---:|
| BenchmarkHTTPRoundTrip | 414 | 423 | 34001 | 37977 |
| BenchmarkHealth | 19 | 19 | 6114 | 6114 |
| BenchmarkRequestProcessing | 47 | 47 | 8794 | 8794 |

## Same woven binary, environment variants (allocs/op)

| benchmark | default (sampling=30) | DD_IAST_ENABLED=false | DD_IAST_REQUEST_SAMPLING=0 |
|---|---:|---:|---:|
| BenchmarkWeakHashNoActiveSpan | 4 | 0 | 4 |
| BenchmarkWeakCipherNoActiveSpan | 5 | 1 | 5 |
| BenchmarkWeakHashActiveSpan | 71 | 56 | 60 |
| BenchmarkWeakCipherActiveSpan | 72 | 57 | 61 |
| BenchmarkHTTPRoundTrip | 447 | 416 | 423 |
