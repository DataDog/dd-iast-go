
set -u
export GOTOOLCHAIN=go1.26.6
W=/tmp/ddiast-review/wt/prop-ranges-fuzz
M=$W/_mut
rsync -a --delete --exclude _mut --exclude '*.log' $W/ $M/
P=$M/internal/taint/ranges
cp $P/canonical.go /tmp/ddiast-review/wt/prop-ranges-fuzz/_canon.orig
cp $P/operations.go /tmp/ddiast-review/wt/prop-ranges-fuzz/_ops.orig
cp $P/marks.go /tmp/ddiast-review/wt/prop-ranges-fuzz/_marks.orig
run() { # name file sed-expr
  cp $W/_canon.orig $P/canonical.go; cp $W/_ops.orig $P/operations.go; cp $W/_marks.orig $P/marks.go
  perl -0pi -e "$3" $P/$2
  if cmp -s $P/$2 $4; then echo "MUTANT $1: NOT APPLIED"; return; fi
  out=$(cd $M && timeout 300 go test -count=1 -timeout 4m -run 'TestReview' ./internal/taint/ranges/ 2>&1)
  if echo "$out" | grep -q '^ok'; then echo "MUTANT $1: SURVIVED"; else echo "MUTANT $1: KILLED :: $(echo "$out" | grep -m1 -E 'op=|Error|FAIL' | cut -c1-200)"; fi
}
run canon-merge-ignores-marks canonical.go 's/previous.SourceID == r.SourceID && previous.Marks == r.Marks \{\n\t\t\t\tcombined/previous.SourceID == r.SourceID {\n\t\t\t\tcombined/' $W/_canon.orig
run coarse-union-marks operations.go 's/marks &= r.Marks/marks |= r.Marks/' $W/_ops.orig
run builder-limit-offbyone operations.go 's/if int\(b.result.count\) >= int\(b.result.limit\)/if int(b.result.count) > int(b.result.limit)/' $W/_ops.orig
run unsafefor-inverted marks.go 's/if r.Marks&bit == 0 \{/if r.Marks&bit != 0 {/' $W/_marks.orig
run marksource-inverted marks.go 's/if !filter \|\| r.SourceID == source/if !filter || r.SourceID != source/' $W/_marks.orig
run window-shift-offbyone operations.go 's/r.Start = outputOffset \+ \(start - low\)/r.Start = outputOffset + (start - low) + 1/' $W/_ops.orig
run canon-later-wins canonical.go 's/fragmentCount := subtractAccepted\(fragments\[:\], candidate, accepted\[:acceptedCount\]\)/fragmentCount := subtractAccepted(fragments[:], candidate, accepted[:0])/' $W/_canon.orig
run repeat-fastpath-limit operations.go 's/return AdoptCanonical\(dst, limit, \[\]Range\{r\}, uint32\(total\)\)/return AdoptCanonical(dst, 64, []Range{r}, uint32(total))/' $W/_ops.orig
rm -rf $M $W/_canon.orig $W/_ops.orig $W/_marks.orig
echo MUTDONE
cd $W
for s in 1 2 3 4 5 6 7 8 9 10; do RANGES_ORACLE_SEED=$s RANGES_ORACLE_CASES=100000 timeout 300 go test -count=1 -timeout 4m -run 'TestReviewOperationsAgainstPerByteOracle' ./internal/taint/ranges/ 2>&1 | tail -1 | sed "s/^/seed=$s /"; done
