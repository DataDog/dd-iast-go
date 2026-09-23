#!/bin/bash
# usage: smoke.sh <binary> <label>
set -u
BIN=$1; L=$2; S=/tmp/ddiast-review/wt/hooks-compile-matrix/smoke; cd /tmp/ddiast-review/wt/hooks-compile-matrix/appsec-go-test-app
rm -f $S/traces.$L.bin
python3 $S/agent.py 18126 $S/traces.$L.bin & AP=$!
DD_TRACE_AGENT_URL=http://127.0.0.1:18126 DD_IAST_ENABLED=true DD_IAST_REQUEST_SAMPLING=100 DD_IAST_DEDUPLICATION_ENABLED=false DD_PROFILING_ENABLED=false DD_INSTRUMENTATION_TELEMETRY_ENABLED=false DD_REMOTE_CONFIGURATION_ENABLED=false $BIN > $S/app.$L.log 2>&1 & PID=$!
for i in $(seq 1 60); do curl -s -o /dev/null http://127.0.0.1:7777/api/health && break; sleep 1; done
{
for u in "/products?category=sneaker" "/products?category=sneaker'%20OR%20'1'='1" "/products/sneaker" "/products/x';select%20*%20from%20'user" "/api/health?extra=%3Becho%20hi" "/register" "/test"; do
  echo "== GET $u"; curl -s -m 20 -w "\nHTTP %{http_code}\n" "http://127.0.0.1:7777$u" | md5
done
} > $S/responses.$L.txt 2>&1
sleep 3; kill -TERM $PID; sleep 3; kill -9 $PID 2>/dev/null; kill $AP
echo "alive-check: $(grep -c panic $S/app.$L.log) panics"; cat $S/responses.$L.txt
echo "iast payload hits: $(grep -a -c -E '_dd.iast|SQL_INJECTION|iast' $S/traces.$L.bin 2>/dev/null)"
grep -a -o -E 'SQL_INJECTION|COMMAND_INJECTION|_dd.iast.enabled|_dd.iast.json' $S/traces.$L.bin 2>/dev/null | sort | uniq -c
