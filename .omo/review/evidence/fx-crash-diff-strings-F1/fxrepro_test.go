package fxfmtrepro

import (
	"context"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

func beginScope(t *testing.T) context.Context {
	t.Helper()
	oldEnabled, oldSampling, oldMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = oldEnabled, oldSampling, oldMax
	})
	ctx, scope, created := request.Begin(context.Background())
	if !created || !scope.Active() {
		t.Fatal("no active request scope")
	}
	t.Cleanup(scope.Finish)
	return ctx
}

const attacker = "1' OR '1'='1"

func TestFmtCoarseOverTaint(t *testing.T) {
	ctx := beginScope(t)
	v := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "q"}, attacker)
	if !taint.IsTaintedString(v) {
		t.Fatal("setup: source value is not tainted")
	}

	cases := []struct {
		name         string
		got          string
		sourceInside bool
	}{
		{"Sprintf-Stringer-sanitize", FormatStringer(v), false},
		{"Sprint-Stringer", SprintStringer(v), false},
		{"Sprintf-%T", FormatType(v), false},
		{"Sprintf-%.0s", FormatZeroPrecision(v), false},
		{"Sprintf-%[2]s-skip", FormatIndexSkip(v, "constant"), false},
		{"control-%d", FormatControl(v), false},
		{"positive-%s", FormatPositive(v), true},
	}
	for _, c := range cases {
		tainted := taint.IsTaintedString(c.got)
		contains := strings.Contains(c.got, attacker)
		t.Logf("%-24s result=%q tainted=%v containsSource=%v", c.name, c.got, tainted, contains)
		if !c.sourceInside && tainted {
			t.Errorf("%s: output %q contains none of the source bytes but is tainted", c.name, c.got)
		}
		if c.sourceInside && !tainted {
			t.Errorf("%s: expected tainted output (positive control failed)", c.name)
		}
	}
}

func TestFmtOverTaintReachesSqlSink(t *testing.T) {
	ctx := beginScope(t)
	v := taint.TaintString(ctx, taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "q"}, attacker)
	query := BuildQuery(v)
	t.Logf("query=%q tainted=%v containsSource=%v", query, taint.IsTaintedString(query), strings.Contains(query, attacker))
	if !taint.IsTaintedString(query) {
		t.Fatal("query not tainted")
	}
	if strings.Contains(query, attacker) {
		t.Fatal("Stringer sanitizer unexpectedly leaked attacker bytes")
	}

	snapshot, status := evidence.CollectString(query, constants.VulnerabilityTypeSqlInjection)
	if status != evidence.StatusCollected {
		t.Fatalf("sink evidence not collected (status=%d)", status)
	}
	t.Logf("CollectString status=%d sources=%d parts=%d", status, snapshot.SourceCount(), snapshot.PartCount())
	for i := 0; i < snapshot.PartCount(); i++ {
		part, ok := snapshot.PartAt(i)
		if !ok {
			continue
		}
		value, ok := snapshot.PartValue(part)
		if ok {
			t.Logf("part[%d]=%q", i, value)
		}
	}
}
