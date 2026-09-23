#!/bin/bash
for t in st-golang-app playground-gin appsec-go-test-app x-exp samber-lo overhead idioms; do
  rm -rf /tmp/ddiast-review/wt/hooks-compile-matrix/gocache-cur
  /tmp/ddiast-review/wt/hooks-compile-matrix/measure.sh $t woven-iast /tmp/ddiast-review/wt/hooks-compile-matrix/gocache-cur go tool orchestrion go build ./... 2>&1 | grep -v MEASURE_DONE
done
rm -rf /tmp/ddiast-review/wt/hooks-compile-matrix/gocache-cur
echo SERIAL_DONE
