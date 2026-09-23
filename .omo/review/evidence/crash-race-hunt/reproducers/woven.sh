#!/bin/bash
# usage: _woven.sh <dir-relative-to-W> <label> <extra go test flags...>
W=/tmp/ddiast-review/wt/crash-race-hunt
dir=$1; label=$2; shift 2
export GOTOOLCHAIN=go1.26.6 GOFLAGS=-p=4
cd "$W/$dir" || exit 1
s=$(date +%s)
/usr/bin/time -l go tool orchestrion go test "$@" > "$W/_logs/woven_$label.out" 2> "$W/_logs/woven_$label.time"
e=$?
{
  echo "=== $dir: go tool orchestrion go test $*"
  echo "exit=$e secs=$(( $(date +%s)-s ))"
  echo "races=$(grep -c 'WARNING: DATA RACE' "$W/_logs/woven_$label.out" "$W/_logs/woven_$label.time" | paste -sd, -)"
  echo "checkptr=$(grep -c 'checkptr' "$W/_logs/woven_$label.out" "$W/_logs/woven_$label.time" | paste -sd, -)"
  grep -E '^(ok|FAIL|---? FAIL|panic)' "$W/_logs/woven_$label.out" | sort | uniq -c | head -20
  grep -E 'maximum resident set size|peak memory footprint' "$W/_logs/woven_$label.time"
} > "$W/_logs/woven_$label.summary"
cat "$W/_logs/woven_$label.summary"
