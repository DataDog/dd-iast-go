Independent verification run, node fx-crash-diff-strings-F1.

Note: fmtrepro_test.go and fmtrepro-run.log (timestamped 14:05, package fmtrepro)
are leftovers from an earlier attempt of this node id, not part of this run.

Private copy: /tmp/ddiast-review/wt/fx-crash-diff-strings-F1 (removed after the run).
Reproducer package: iast/internal/fxfmtrepro/ (fxrepro.go = woven fmt call sites,
fxrepro_test.go = taint oracle + SQL-sink evidence path). Both copied here.

Command (foreground, one heavy command at a time, /usr/bin/time -l):
  cd /tmp/ddiast-review/wt/fx-crash-diff-strings-F1 && /usr/bin/time -l \
    env GOFLAGS=-p=4 GOTOOLCHAIN=go1.26.6 \
    go tool orchestrion go test -v -count=1 -timeout 15m -run 'TestFmt' ./iast/internal/fxfmtrepro/

Result: TestFmtCoarseOverTaint FAILED (5 over-taint cases), TestFmtOverTaintReachesSqlSink PASSED.
Peak RSS 105 MB. Full captured output: woven-go1.26.6.log.

Key output lines (my own reproducer, woven build, go1.26.6):
  Sprintf-Stringer-sanitize result="level=AUDIT_OK" tainted=true containsSource=false
  Sprint-Stringer           result="AUDIT_OK"      tainted=true containsSource=false
  Sprintf-%T                result="type=string"   tainted=true containsSource=false
  Sprintf-%.0s              result="xy"            tainted=true containsSource=false
  Sprintf-%[2]s-skip        result="constant"      tainted=true containsSource=false
  control-%d                result="n=12"          tainted=false containsSource=false
  positive-%s               result="q=1' OR '1'='1" tainted=true containsSource=true
  query="SELECT * FROM t WHERE level='AUDIT_OK'" tainted=true containsSource=false
  CollectString status=1 sources=1 parts=1        (status 1 = StatusCollected)
  part[0]="SELECT * FROM t WHERE level='AUDIT_OK'"

The auditLevel Stringer maps attacker input "1' OR '1'='1" to the constant
"AUDIT_OK" (sanitizing idiom). The woven fmt result contains none of the source
bytes yet is fully tainted, and evidence.CollectString (the exact first step of
iast/database/sql.Report) collects a vulnerability snapshot for it.

Note: this run exercises the REAL woven surface (direct fmt.Sprintf/fmt.Sprint
call sites replaced by iast/propagation.FmtSprint*), which closes the gap noted
in prop-string-coarse.md ("End-to-end woven run of F1 through a real fmt call
was not done").
