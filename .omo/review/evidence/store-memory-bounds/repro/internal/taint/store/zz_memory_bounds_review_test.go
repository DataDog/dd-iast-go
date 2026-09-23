package store_test

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

func heapInuse() uint64 {
	runtime.GC()
	debug.FreeOSMemory()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapInuse
}

func TestReviewStoreSaturation(t *testing.T) {
	s := store.New()
	owners := make([]*store.Owner, store.MaxOwners)
	for i := range owners {
		owners[i] = s.Acquire()
		if owners[i].Disabled() {
			t.Fatalf("owner %d not admitted", i)
		}
	}
	base := heapInuse()
	accepted := 0
	for i, owner := range owners {
		for root := 0; root < 32; root++ {
			value, ref, ok := owner.TaintString(strings.Repeat(string(byte('a'+i%26)), 4096), 0)
			if !ok {
				t.Fatalf("root %d/%d rejected, charged=%d values=%d", i, root, s.ProcessCharged(), s.ProcessValues())
			}
			accepted++
			for offset := 1; offset < 8; offset++ {
				key, valid := store.StringKey(value[offset:])
				if !valid || !owner.Derive(key, ref) {
					t.Fatalf("window %d/%d/%d rejected", i, root, offset)
				}
				accepted++
			}
		}
	}
	if accepted != store.ProcessValueLimit || s.ProcessCharged() != store.ProcessRootBytes || s.ProcessValues() != store.ProcessValueLimit {
		t.Fatalf("unexpected saturation: accepted=%d charged=%d values=%d", accepted, s.ProcessCharged(), s.ProcessValues())
	}
	extra, _, ok := owners[0].TaintString("extra-root", 0)
	if ok || extra != "extra-root" {
		t.Fatal("root accepted beyond global byte budget or changed value")
	}
	saturated := heapInuse()
	t.Logf("store sizeof=%d owners=%d roots=%d values=%d charged=%d baseline=%d saturated=%d delta=%d overflowFree=%d",
		unsafe.Sizeof(store.Store{}), len(owners), store.MaxOwners*32, s.ProcessValues(), s.ProcessCharged(), base, saturated, saturated-base, s.Stats().OverflowFree)
	for _, owner := range owners {
		owner.Finish()
	}
	if s.ProcessCharged() != 0 || s.ProcessValues() != 0 {
		t.Fatal("finish did not release charges")
	}
	after := heapInuse()
	t.Logf("store finished heapInuse=%d released=%d charged=%d values=%d", after, saturated-after, s.ProcessCharged(), s.ProcessValues())
	runtime.KeepAlive(s)
}

func TestReviewManagerSourcesSaturation(t *testing.T) {
	m := request.NewManager(nil)
	analyses := make([]request.Analysis, request.MaxAnalyses)
	for i := range analyses {
		var ok bool
		analyses[i], ok = m.Acquire(64)
		if !ok {
			t.Fatalf("analysis %d not admitted", i)
		}
	}
	base := heapInuse()
	for i, analysis := range analyses {
		for source := 0; source < request.MaxSources; source++ {
			value := fmt.Sprintf("value-%03d", source)
			if _, ok := analysis.TaintString(constants.OriginHttpRequestHeader, fmt.Sprintf("name-%03d", source), value); !ok {
				t.Fatalf("source %d/%d rejected", i, source)
			}
		}
		if analysis.SourceCount() != request.MaxSources {
			t.Fatalf("source table count=%d", analysis.SourceCount())
		}
		if _, ok := analysis.TaintString(constants.OriginHttpRequestHeader, "one-more", "unseen-value"); ok {
			t.Fatal("source inserted beyond source table limit")
		}
	}
	saturated := heapInuse()
	t.Logf("manager sizeof=%d analyses=%d sources=%d charged=%d values=%d baseline=%d saturated=%d delta=%d",
		unsafe.Sizeof(request.Manager{}), len(analyses), len(analyses)*request.MaxSources,
		m.Store().ProcessCharged(), m.Store().ProcessValues(), base, saturated, saturated-base)
	for _, analysis := range analyses {
		analysis.Finish()
	}
	after := heapInuse()
	t.Logf("manager finished heapInuse=%d released=%d charged=%d values=%d", after, saturated-after, m.Store().ProcessCharged(), m.Store().ProcessValues())
	runtime.KeepAlive(m)
}

func bindLargeReader(owner *store.Owner, bytes int) bool {
	reader := &struct{ Payload []byte }{Payload: make([]byte, bytes)}
	for i := range reader.Payload {
		reader.Payload[i] = 1
	}
	return store.BindObjectValue(owner, reader, store.BindingReader)
}

func TestReviewUnchargedReaderAnchor(t *testing.T) {
	s := store.New()
	owner := s.Acquire()
	base := heapInuse()
	const retained = 80 << 20
	if !bindLargeReader(owner, retained) {
		t.Fatal("reader binding rejected")
	}
	anchored := heapInuse()
	t.Logf("reader anchor retainedPayload=%d charged=%d baseline=%d anchored=%d delta=%d boundBytes=%d",
		retained, s.ProcessCharged(), base, anchored, anchored-base, store.ProcessRootBytes)
	if anchored-base < retained/2 || s.ProcessCharged() != 0 {
		t.Fatal("reader retention did not reproduce")
	}
	owner.Finish()
	after := heapInuse()
	t.Logf("reader finished heapInuse=%d released=%d", after, anchored-after)
	if anchored-after < retained/2 {
		t.Fatal("reader graph not released by Finish")
	}
	runtime.KeepAlive(s)
}
