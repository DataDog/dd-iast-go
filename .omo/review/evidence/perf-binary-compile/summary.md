# perf-binary-compile measurements (GOTOOLCHAIN=go1.26.6, GOFLAGS=-p=4, fresh GOCACHE per cold build, shared machine)

| build | rc | wall s | user+sys s | max RSS MB | binary bytes | cold GOCACHE MB | loadavg before |
|---|---:|---:|---:|---:|---:|---:|---|
| itapp-bootstrap-plain | 0 | 4.3 | 3.7 | 302 | 1,749,218 | 20 | { 60.87 56.80 48.45 } |
| itapp-test-plain | 0 | 116.4 | 86.2 | 397 | 19,921,106 | 367 | { 58.64 56.41 48.36 } |
| overhead-test-plain | 0 | 11.39 | 57.7 | 383 | 18,273,618 | 357 | { 110.23 76.62 57.22 } |
| orchestrion-tool-selfbuild | 0 | 120.02 | 111.6 | 983 | 52,836,898 | 540 | { 68.75 69.80 55.42 } |
| itapp-bootstrap-control | 0 | 44.36 | 156.4 | 916 | 21,098,994 | 905 | { 83.27 75.39 59.39 } |
| itapp-bootstrap-full | 0 | 167.82 | 283.2 | 966 | 22,194,578 | 917 | { 53.45 68.93 57.85 } |
| itapp-test-full | 0 | 148.54 | 284.6 | 1090 | 20,065,122 | 938 | { 58.12 69.42 60.25 } |
| overhead-test-control | 0 | 90.14 | 278.3 | 894 | 19,951,154 | 934 | { 51.28 67.55 61.27 } |
| overhead-test-full | 0 | 78.71 | 258.4 | 927 | 20,313,298 | 941 | { 46.84 64.60 60.88 } |
| overhead-test-full-warm-noop | 0 | 6.67 | 16.1 | 410 | 20,313,298 | 941 | { 29.06 55.30 57.69 } |
| overhead-test-full-warm-touch | 0 | 13.83 | 17.4 | 412 | 20,313,298 | 942 | { 27.13 54.47 57.38 } |

| comparison | size ratio | size delta (bytes) | wall ratio | CPU (user+sys) ratio |
|---|---:|---:|---:|---:|
| itapp-bootstrap-full / itapp-bootstrap-plain | 12.69x | +20,445,360 | 39.0x | 75.7x |
| itapp-bootstrap-full / itapp-bootstrap-control | 1.05x | +1,095,584 | 3.8x | 1.8x |
| itapp-bootstrap-control / itapp-bootstrap-plain | 12.06x | +19,349,776 | 10.3x | 41.8x |
| itapp-test-full / itapp-test-plain | 1.01x | +144,016 | 1.3x | 3.3x |
| overhead-test-full / overhead-test-plain | 1.11x | +2,039,680 | 6.9x | 4.5x |
| overhead-test-full / overhead-test-control | 1.02x | +362,144 | 0.9x | 0.9x |
| overhead-test-control / overhead-test-plain | 1.09x | +1,677,536 | 7.9x | 4.8x |

## go tool nm -size totals by symbol owner (bytes)
- itapp-bootstrap-control: {'other': 49197552, 'dd-trace-go': 866223, 'orchestrion': 16}
- itapp-bootstrap-full: {'other': 49740007, 'dd-trace-go': 954403, 'dd-iast-go': 160521, 'orchestrion': 16}
- overhead-test-control: {'other': 48547801, 'dd-trace-go': 540483, 'dd-iast-go': 89385, 'orchestrion': 16}
- overhead-test-full: {'other': 48720490, 'dd-trace-go': 545819, 'dd-iast-go': 163101, 'orchestrion': 16}
- itapp-test-plain: {'other': 48549816, 'dd-trace-go': 363907, 'dd-iast-go': 208545, 'orchestrion': 24}
- itapp-test-full: {'other': 48599589, 'dd-trace-go': 365988, 'dd-iast-go': 258373, 'orchestrion': 16}
