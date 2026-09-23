#!/bin/bash
# usage: campaign.sh <gomaxprocs> <total-seconds> <per-run-duration> <logdir>
P=$1; TOTAL=$2; PER=$3; LOG=$4
mkdir -p "$LOG"
cd /tmp/ddiast-review/wt/store-stress/internal/taint/store
end=$(( $(date +%s) + TOTAL ))
i=0
while [ $(date +%s) -lt $end ]; do
  seed=$(( ( $(date +%s%N 2>/dev/null || date +%s) + i * 7919 + P * 104729 ) % 1000000007 ))
  i=$((i+1))
  STORE_STRESS=1 STRESS_SEED=$seed STRESS_DURATION=$PER GOMAXPROCS=$P timeout 300 /tmp/ddiast-review/wt/store-stress/stress.test -test.run '^TestReviewStoreStress$' -test.v > "$LOG/p$P-seed$seed.log" 2>&1
  rc=$?
  race=$(grep -c "WARNING: DATA RACE" "$LOG/p$P-seed$seed.log")
  viol=$(grep -c "^VIOLATION" "$LOG/p$P-seed$seed.log")
  panic=$(grep -c "PANIC\|^panic:" "$LOG/p$P-seed$seed.log")
  summary=$(grep -o "seed=[0-9]* workers=[0-9]* collide=[a-z]* ops=[0-9]*" "$LOG/p$P-seed$seed.log" | head -1)
  echo "GOMAXPROCS=$P seed=$seed rc=$rc races=$race violations=$viol panics=$panic $summary" | tee -a "$LOG/summary.txt"
done
