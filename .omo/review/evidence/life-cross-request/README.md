# life-cross-request evidence

Files:
- `zz_review_crossreq.go`: woven helpers. Place in `iast/integration/testapp/` (package `testapp`, the woven root package).
- `zz_review_crossreq_test.go`: two-request harness plus reproducers R1-R5. Place in `iast/integration/testapp/` (package `testapp_test`, which is not woven, so plain calls model un-woven dependency code).
- `run1-go1.26.6.log`: first run (`-count=1 -v`, wrapped in `/usr/bin/time -l`; peak RSS 360 MB).
- `run2-count3-go1.26.6.log`: `-count=3` run. The same 3 subtests fail on every iteration, so the result is deterministic.

Command, run from a private copy of HEAD 2e23b46:

    cd iast/integration/testapp
    GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 go tool orchestrion go test -count=1 -timeout 15m -run TestReview -v .

Each test sends two real requests through the woven `net/http` server. Both requests are analyzed and each has its own root span. Request A carries the input `x' OR '1'='1' --comment!`. Request B executes the constant query `SELECT id FROM customers` through `database/sql`. A failing subtest means B's span carries an SQL_INJECTION finding that lists A's source value.
