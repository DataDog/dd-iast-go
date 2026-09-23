package request

import (
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/stretchr/testify/require"
)

func TestBoundsManagerLayout(t *testing.T) {
	t.Logf("Source=%d Table=%d analysisSlot=%d Manager=%d Analysis=%d Scope=%d fixedAndRoots=%d",
		unsafe.Sizeof(Source{}), unsafe.Sizeof(Table{}), unsafe.Sizeof(analysisSlot{}),
		unsafe.Sizeof(Manager{}), unsafe.Sizeof(Analysis{}), unsafe.Sizeof(Scope{}),
		unsafe.Sizeof(store.Store{})+unsafe.Sizeof(Manager{})+store.ProcessRootBytes)
	for _, limit := range []int{0, 1, 2, 64, 65} {
		m := NewManager(nil)
		var analyses []Analysis
		for {
			a, ok := m.Acquire(limit)
			if !ok {
				break
			}
			analyses = append(analyses, a)
		}
		require.Len(t, analyses, min(limit, MaxAnalyses))
		t.Logf("requested=%d admitted=%d", limit, len(analyses))
		for _, a := range analyses {
			a.Finish()
		}
	}
}

func TestBoundsMutableSourceCharge(t *testing.T) {
	m := NewManager(nil)
	a, ok := m.Acquire(64)
	require.True(t, ok)
	data := make([]byte, store.MaxRootBytes)
	name := string(make([]byte, store.MaxRootBytes))
	_, ok = a.TaintBytes(constants.OriginHttpRequestBody, name, data)
	require.True(t, ok)
	require.Equal(t, int64(store.MaxRootChargeBytes), m.Store().ProcessCharged())
	t.Logf("sourceBytes cap=%d name=%d immutableCopy=%d charge=%d", cap(data), len(name), len(data), m.Store().ProcessCharged())
	a.Finish()
	require.Zero(t, m.Store().ProcessCharged())
}
