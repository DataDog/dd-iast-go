package propagation_test

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iastprop "github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	internal "github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

func reviewConfig(t *testing.T, maxRequests int) {
	t.Helper()
	pe, ps, pm := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, maxRequests
	t.Cleanup(func() { config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = pe, ps, pm })
}

type reviewRange struct {
	start, length uint32
	source        string
	ownerID       uint64
}

func reviewVisit(value string) []reviewRange {
	var out []reviewRange
	request.VisitString(value, func(r request.ResolvedRange) bool {
		out = append(out, reviewRange{r.Start, r.Length, strings.Clone(r.Source.Value), r.OwnerID})
		return true
	})
	return out
}

func reviewBegin(t *testing.T) (*request.Scope, request.Analysis, uint64) {
	t.Helper()
	_, scope, created := request.Begin(context.Background())
	if !created || !scope.Active() {
		t.Fatalf("scope not active: created=%v", created)
	}
	a, _ := scope.Analysis()
	_, id, _, ok := a.Identity()
	if !ok {
		t.Fatal("no identity")
	}
	return scope, a, id
}

// Two concurrent owners, one concatenation, then successive owner reuse.
func TestReviewCrossOwnerConcatAndReuse(t *testing.T) {
	reviewConfig(t, 64)
	scopeA, a, idA := reviewBegin(t)
	scopeB, b, idB := reviewBegin(t)
	aVal, ok := a.TaintString(constants.OriginHttpRequestHeader, "ha", "alpha-AAAA")
	if !ok {
		t.Fatal("taint A")
	}
	bVal, ok := b.TaintString(constants.OriginHttpRequestHeader, "hb", "bravo-BBBB")
	if !ok {
		t.Fatal("taint B")
	}
	joined := iastprop.Concat2(aVal, bVal)
	got := reviewVisit(joined)
	t.Logf("both active: %+v (idA=%d idB=%d)", got, idA, idB)
	want := map[reviewRange]bool{{0, 10, "alpha-AAAA", idA}: true, {10, 10, "bravo-BBBB", idB}: true}
	if len(got) != 2 || !want[got[0]] || !want[got[1]] {
		t.Fatalf("cross-owner concat provenance wrong: %+v", got)
	}
	var sb strings.Builder
	iastprop.BuilderWriteString(&sb, aVal)
	iastprop.BuilderWriteString(&sb, "-")
	iastprop.BuilderWriteString(&sb, bVal)
	built := iastprop.BuilderString(&sb)
	t.Logf("builder both active: %+v", reviewVisit(built))
	for _, r := range reviewVisit(built) {
		if built[r.start:r.start+r.length] != r.source {
			t.Fatalf("builder range source mismatch: %+v", r)
		}
	}

	scopeA.Finish()
	got = reviewVisit(joined)
	t.Logf("after A finish: %+v", got)
	if len(got) != 1 || got[0] != (reviewRange{10, 10, "bravo-BBBB", idB}) {
		t.Fatalf("after A finish want only B range: %+v", got)
	}
	if r := reviewVisit(aVal); len(r) != 0 {
		t.Fatalf("A value still tainted after A finish: %+v", r)
	}
	scopeB.Finish()
	if r := reviewVisit(joined); len(r) != 0 {
		t.Fatalf("joined still tainted after both finish: %+v", r)
	}

	// Successive owner: reuses slot 0 / permit 0; first root is again rootID 0 gen 1
	// and source ID 0, identical to A's stale slot coordinates.
	scopeC, c, idC := reviewBegin(t)
	defer scopeC.Finish()
	cVal, ok := c.TaintString(constants.OriginHttpRequestHeader, "hc", "charl-CCCC")
	if !ok {
		t.Fatal("taint C")
	}
	for name, v := range map[string]string{
		"stale A value": aVal, "stale B value": bVal, "stale joined": joined, "stale built": built,
		"concat(stale A)":  iastprop.Concat2(aVal, "-x"),
		"slice(stale A)":   internal.CopyString(aVal, strings.Clone(aVal)),
		"coarse(stale A)":  internal.CoarseString(fmt.Sprint(aVal, "!"), aVal),
		"replace(stale A)": internal.ReplaceString(aVal, "A", "Z", strings.ReplaceAll(aVal, "A", "Z"), -1),
		"builder(stale AB)": func() string {
			var s strings.Builder
			iastprop.BuilderWriteString(&s, aVal)
			return iastprop.BuilderString(&s)
		}(),
	} {
		if r := reviewVisit(v); len(r) != 0 {
			t.Fatalf("%s tainted under successor owner C (id %d): %+v", name, idC, r)
		}
	}
	if r := reviewVisit(cVal); len(r) != 1 || r[0].source != "charl-CCCC" || r[0].ownerID != idC {
		t.Fatalf("C provenance wrong: %+v", r)
	}
	st := request.ActiveStore()
	for _, v := range []string{aVal, bVal, joined} {
		key, _ := store.StringKey(v)
		var snap store.Snapshot
		st.Lookup(key, &snap)
		if snap.Len() != 0 {
			t.Fatalf("store Lookup returned %d entries for a stale key under successor", snap.Len())
		}
	}
	t.Logf("successor C id=%d isolated from stale A/B values", idC)
}

// Request A publishes a tainted value into a shared global while it is still
// running. Unsampled traffic (no scope at all) that merely propagates the shared
// value creates state charged to owner A, exhausting A's per-owner writer table
// (MaxWriters=8) so A's own later builder provenance is dropped.
func TestReviewForeignTrafficExhaustsOwnerBudget(t *testing.T) {
	reviewConfig(t, 64)
	scopeA, a, idA := reviewBegin(t)
	defer scopeA.Finish()
	shared, ok := a.TaintString(constants.OriginHttpRequestHeader, "x-tenant", "tenant-from-A")
	if !ok {
		t.Fatal("taint A")
	}
	// Unsampled request goroutines: no request scope, just builders over the global.
	foreign := make([]*strings.Builder, 0, store.MaxWriters)
	for i := 0; i < store.MaxWriters; i++ {
		sb := new(strings.Builder)
		iastprop.BuilderWriteString(sb, "SELECT * FROM t WHERE tenant='")
		iastprop.BuilderWriteString(sb, shared)
		foreign = append(foreign, sb)
	}
	// Request A itself now builds a query from its own tainted value.
	mine, ok := a.TaintString(constants.OriginHttpRequestParameter, "id", "1 OR 1=1")
	if !ok {
		t.Fatal("taint A param")
	}
	var own strings.Builder
	iastprop.BuilderWriteString(&own, "SELECT * FROM users WHERE id=")
	iastprop.BuilderWriteString(&own, mine)
	query := iastprop.BuilderString(&own)
	r := reviewVisit(query)
	t.Logf("owner A id=%d: foreign builders=%d; A's own builder query tainted ranges=%+v", idA, len(foreign), r)
	firstForeign := iastprop.BuilderString(foreign[0])
	t.Logf("foreign (unsampled) builder result ranges=%+v", reviewVisit(firstForeign))
	if len(r) == 0 {
		t.Errorf("A's own supported builder propagation was dropped after unsampled traffic filled A's writer table")
	}
}

// Late goroutines keep propagating values of finished owners while the owner slot
// is continuously reused (MaxConcurrentRequests=1). Every tainted result must be
// attributed to a source whose value equals the tainted bytes; any mismatch means
// an old owner's source IDs were published into the successor owner.
func TestReviewOwnerEndsDuringPropagationStress(t *testing.T) {
	reviewConfig(t, 1)
	budget := 20 * time.Second
	if v := os.Getenv("REVIEW_BUDGET"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatal(err)
		}
		budget = d
	}
	type cycleValue struct{ value string }
	var current atomic.Pointer[cycleValue]
	var stop atomic.Bool
	var ops, taintedResults, mismatches atomic.Uint64
	var firstMu sync.Mutex
	var first []string
	record := func(kind, value string, r reviewRange) {
		mismatches.Add(1)
		firstMu.Lock()
		if len(first) < 10 {
			first = append(first, fmt.Sprintf("%s: value=%q range=[%d,+%d) resolvedSource=%q owner=%d", kind, value, r.start, r.length, r.source, r.ownerID))
		}
		firstMu.Unlock()
	}
	// srcLen: the leading bytes that are the (whole) source value; cover: the
	// maximum range end allowed (== srcLen for exact ops, len(value) for coarse).
	check := func(kind, value string, srcLen, cover int) {
		rs := reviewVisit(value)
		if len(rs) > 0 {
			taintedResults.Add(1)
		}
		for _, r := range rs {
			if r.start+r.length > uint32(len(value)) || r.source != value[:srcLen] || int(r.start+r.length) > cover {
				record(kind, value, r)
			}
		}
	}
	workers := max(4, runtime.GOMAXPROCS(0)-2)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for !stop.Load() {
				cv := current.Load()
				if cv == nil {
					continue
				}
				v := cv.value
				switch w % 3 {
				case 0:
					var sb strings.Builder
					iastprop.BuilderWriteString(&sb, v)
					iastprop.BuilderWriteString(&sb, "|clean-tail")
					check("builder", iastprop.BuilderString(&sb), len(v), len(v))
				case 1:
					check("concat", iastprop.Concat2(v, "|clean-tail"), len(v), len(v))
				case 2:
					check("coarse", internal.CoarseString(v+"|clean-tail", v), len(v), len(v)+len("|clean-tail"))
				}
				ops.Add(1)
			}
		}(w)
	}
	deadline := time.Now().Add(budget)
	cycles := 0
	for time.Now().Before(deadline) {
		_, scope, created := request.Begin(context.Background())
		if !created {
			t.Fatal("scope not created")
		}
		if a, ok := scope.Analysis(); ok {
			if v, ok := a.TaintString(constants.OriginHttpRequestHeader, "h", fmt.Sprintf("SRC-%010d-payload", cycles)); ok {
				current.Store(&cycleValue{v})
			}
		}
		for i := 0; i < 4; i++ {
			runtime.Gosched()
		}
		scope.Finish()
		cycles++
	}
	stop.Store(true)
	wg.Wait()
	t.Logf("cycles=%d ops=%d taintedResults=%d mismatches=%d", cycles, ops.Load(), taintedResults.Load(), mismatches.Load())
	for _, f := range first {
		t.Log(f)
	}
	if mismatches.Load() != 0 {
		t.Fatalf("cross-owner provenance bleed: %d results attributed to a foreign/successor source", mismatches.Load())
	}
}
