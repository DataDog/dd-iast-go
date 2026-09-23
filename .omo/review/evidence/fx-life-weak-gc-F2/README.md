# Independent F2 reproduction

`review_fx_late_bind_test.go` is an independent reproducer written for this
verification node. It starts a root span under an active request scope, closes
the root, then starts a child from the retained request context.

The plain internal lifecycle reproducer fails on both pinned Go 1.26.6 and
the workstation Go 1.27.0. The focused woven Go 1.26.6 run also fails, proving
that the actual `Span.Finish` hook does not prevent an open late annotation from
accepting a commit after its root has already finished.

See `plain-go1266.log`, `plain-go1270.log`, and `woven-go1266.log` for commands
and captured failure lines.
