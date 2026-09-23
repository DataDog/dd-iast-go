#!/bin/bash
# usage: run.sh <dir> <toolchain> <label> <cmd...>
d=$1; tc=$2; label=$3; shift 3
mkdir -p /tmp/ddiast-review/wt/hooks-compile-matrix/logs
log=/tmp/ddiast-review/wt/hooks-compile-matrix/logs/$(echo $d | tr / _).$label.log
cd /tmp/ddiast-review/wt/hooks-compile-matrix/$d
export GOTOOLCHAIN=$tc GOFLAGS=-mod=mod
start=$(date +%s)
{ echo "Command: cd $d && GOTOOLCHAIN=$tc $*"; echo "go version: $(go version)"; echo; } > $log
timeout 1500 "$@" >> $log 2>&1
ec=$?
echo >> $log; echo "Exit status: $ec  (elapsed $(( $(date +%s)-start ))s)" >> $log
echo "$d $label exit=$ec elapsed=$(( $(date +%s)-start ))s"
