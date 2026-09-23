#!/bin/bash
for t in nho/net-http-orchestrion go-sqlite3 st-golang-app playground-gin appsec-go-test-app samber-lo overhead; do
  rm -rf /tmp/ddiast-review/wt/hooks-compile-matrix/gocache-cur
  /tmp/ddiast-review/wt/hooks-compile-matrix/measure.sh $t plain-126 /tmp/ddiast-review/wt/hooks-compile-matrix/gocache-cur go build ./... 2>&1 | grep -E "exit=|maximum|peak tree"
done
rm -rf /tmp/ddiast-review/wt/hooks-compile-matrix/gocache-cur; echo RUN_DONE
