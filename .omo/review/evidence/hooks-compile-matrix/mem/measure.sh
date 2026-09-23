#!/bin/bash
# usage: measure.sh <dir> <label> <gocache> <cmd...>   (serial, one at a time)
d=$1; label=$2; gc=$3; shift 3
M=/tmp/ddiast-review/wt/hooks-compile-matrix/mem; mkdir -p $M; base=$M/$(echo $d | tr / _).$label
cd /tmp/ddiast-review/wt/hooks-compile-matrix/$d || exit 1
export GOTOOLCHAIN=${TC:-go1.26.6} GOFLAGS=-mod=mod GOCACHE=$gc
mkdir -p $gc
{ echo "Command: cd $d && GOTOOLCHAIN=${TC:-go1.26.6} GOCACHE=$gc /usr/bin/time -l timeout 1320 $*"; echo "go version: $(go version)"; echo "start: $(date)"; uptime; } > $base.log
/usr/bin/time -l timeout 1320 "$@" >> $base.log 2> $base.time & BP=$!
python3 /tmp/ddiast-review/wt/hooks-compile-matrix/sampler.py $BP $base &
SP=$!
wait $BP; ec=$?
wait $SP
{ echo "Exit status: $ec"; echo "end: $(date)"; } >> $base.log
echo "$d $label exit=$ec"; grep -E "real|maximum resident" $base.time; python3 -c "import json;d=json.load(open('$base.summary.json'));print('peak tree MB',d['peak_tree_rss_kb']//1024,'at',d['peak_tree_at_s'],'s');[print(' ',v//1024,'MB',k) for k,v in d['top_process_peaks_kb'][:8]]"
echo MEASURE_DONE
