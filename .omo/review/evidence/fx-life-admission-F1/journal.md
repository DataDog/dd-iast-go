# Independent admission-lifecycle verification

Target: HEAD `2e23b4614320defd0d32177a69888dcab73f4d11`.
All build/test work is confined to `/tmp/ddiast-review/wt/fx-life-admission-F1`.

Hypotheses:

1. Cancellation already frees the analysis through an alternate callback.
   Distinguish by observing live scope state and later woven HTTP admission
   after server-side context cancellation has been acknowledged.
2. There is a genuinely lost permit that remains unavailable after handler
   completion. Distinguish by unblocking the handlers, observing the real
   production finish callback, and issuing another HTTP request.
3. The permit is still owned by a running handler, following the documented
   deferred-completion design. Distinguish by the same admission recovery,
   continued source provenance in canceled handlers, and the lifecycle plan.

Artifacts: independent `zz_fx_life_admission_test.go`, woven Go 1.26.6/1.27.0
output, and verification report. The only runtime observer delegates to the
original finish callback before publishing an event; it adds no release path.
Tests use channel events and bounded timeouts, with no polling or sleeps.
Sampling alone is set to 100% for determinism; enabled and capacity retain
their checked defaults (`true`, `2`).
