#!/bin/bash
set -u
cd <private-copy>/out
OUT=results.jsonl; : > $OUT; rm -f stderr-*.txt
BASE="DD_TRACE_STARTUP_LOGS=false DD_INSTRUMENTATION_TELEMETRY_ENABLED=false"
SAT="DD_IAST_REQUEST_SAMPLING=100 DD_IAST_DEDUPLICATION_ENABLED=false DD_IAST_MAX_RANGE_COUNT=64 DD_IAST_VULNERABILITIES_PER_REQUEST=64"
run() { # variant bin env scenario [extra]
  local v=$1 bin=$2 envs=$3 sc=$4 extra=${5:-} n=2000 warm=200
  case $sc in worst|overcap) n=300; warm=30;; esac
  if [ -n "$extra" ]; then case $sc in worst|overcap) n=20; warm=5;; *) n=300; warm=20;; esac; fi
  env $BASE $envs ./$bin -variant=$v -scenario=$sc -n=$n -warm=$warm $extra >> $OUT 2>>stderr-$v-$sc.txt || echo "FAIL $v $sc" >> $OUT
}
for sc in idle clean safe typical worst; do run plain memprobe-plain "" $sc; done
for sc in idle clean safe typical worst; do run woven-off memprobe-woven "DD_IAST_ENABLED=false" $sc; done
for sc in idle clean safe typical worst; do run woven-s0 memprobe-woven "DD_IAST_REQUEST_SAMPLING=0" $sc; done
for sc in idle clean safe typical typical49 worst overcap; do run woven-s100 memprobe-woven "DD_IAST_REQUEST_SAMPLING=100" $sc; done
for sc in typical worst; do run woven-s100-nodedup memprobe-woven "DD_IAST_REQUEST_SAMPLING=100 DD_IAST_DEDUPLICATION_ENABLED=false" $sc; done
for sc in typical typical49 worst overcap; do run woven-saturated memprobe-woven "$SAT" $sc; done
for sc in typical worst; do run woven-defaults memprobe-woven "" $sc; done
mkdir -p prof; : > prof/results.jsonl
OUT=prof/results.jsonl
run plain memprobe-plain "" typical "-memprofile=prof/plain-typical.pprof"
run woven-off memprobe-woven "DD_IAST_ENABLED=false" typical "-memprofile=prof/off-typical.pprof"
run woven-s0 memprobe-woven "DD_IAST_REQUEST_SAMPLING=0" typical "-memprofile=prof/s0-typical.pprof"
run woven-s100 memprobe-woven "DD_IAST_REQUEST_SAMPLING=100" typical "-memprofile=prof/s100-typical.pprof"
run woven-s100-nodedup memprobe-woven "DD_IAST_REQUEST_SAMPLING=100 DD_IAST_DEDUPLICATION_ENABLED=false" typical "-memprofile=prof/nodedup-typical.pprof"
run woven-s0 memprobe-woven "DD_IAST_REQUEST_SAMPLING=0" clean "-memprofile=prof/s0-clean.pprof"
run woven-off memprobe-woven "DD_IAST_ENABLED=false" clean "-memprofile=prof/off-clean.pprof"
run plain memprobe-plain "" worst "-memprofile=prof/plain-worst.pprof"
run woven-saturated memprobe-woven "$SAT" worst "-memprofile=prof/sat-worst.pprof"
echo DONE
