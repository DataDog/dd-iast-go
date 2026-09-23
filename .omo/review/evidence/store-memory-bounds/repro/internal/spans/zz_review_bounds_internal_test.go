package spans

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/vulnerability/dedup"
	"github.com/stretchr/testify/require"
)

func eventBoundsHeap() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse
}

func TestBoundsAnnotationLayout(t *testing.T) {
	t.Logf("Annotation=%d Event=%d SourceIdentity=%d ModelSource=%d Vulnerability=%d Evidence=%d ValuePart=%d Location=%d ownerBinding=%d ownerPointers=%d DedupSet=%d vulnType=%d typeCount=%d",
		unsafe.Sizeof(Annotation{}), unsafe.Sizeof(model.Event{}), unsafe.Sizeof(SourceIdentity{}),
		unsafe.Sizeof(model.Source{}), unsafe.Sizeof(model.Vulnerability{}), unsafe.Sizeof(model.Evidence{}),
		unsafe.Sizeof(model.ValuePart{}), unsafe.Sizeof(model.Location{}), unsafe.Sizeof(ownerSpanBinding{}),
		unsafe.Sizeof(ownerSpans), unsafe.Sizeof(dedup.Set{}), unsafe.Sizeof(constants.VulnerabilityType(0)), constants.VulnerabilityTypeCount)
}

// +checklocksignore
func TestBoundsEventSourceBudgets(t *testing.T) {
	require.Zero(t, processEventSourceBytes.Load())
	for _, sourceSize := range []int{16, 1024} {
		t.Run(fmt.Sprintf("sourceSize=%d", sourceSize), func(t *testing.T) {
			before := eventBoundsHeap()
			var anns [64]*Annotation
			accepted := 0
			for i := range anns {
				ann := &Annotation{Sampled: true}
				anns[i] = ann
				sources := make([]TaintedSource, MaxEventSources)
				for j := range sources {
					name := fmt.Sprintf("%04d", j)
					value := strings.Repeat("v", sourceSize-len(name))
					sources[j] = TaintedSource{
						Identity: SourceIdentity{Origin: constants.OriginHttpRequestParameter, Name: name, Value: value},
						Model:    model.NewSourceString(constants.OriginHttpRequestParameter, name, value),
					}
				}
				commit := TaintedCommit{Vulnerability: model.Vulnerability{Hash: int32(i + 1)}, Sources: sources}
				ok := ann.TryCommitTainted(&commit, nil)
				if ok {
					accepted++
					require.Len(t, ann.sourceIdentities, MaxEventSources)
					require.Equal(t, int64(MaxEventSources*sourceSize), ann.sourceIdentityBytes)
					extra := TaintedCommit{Vulnerability: model.Vulnerability{Hash: 1000}, Sources: []TaintedSource{{
						Identity: SourceIdentity{Origin: constants.OriginHttpRequestParameter, Name: "new", Value: "new"},
					}}}
					require.False(t, ann.TryCommitTainted(&extra, nil))
				}
			}
			want := min(64, MaxProcessEventSourceBytes/(MaxEventSources*sourceSize))
			require.Equal(t, want, accepted)
			require.Equal(t, int64(accepted*MaxEventSources*sourceSize), processEventSourceBytes.Load())
			after := eventBoundsHeap()
			t.Logf("sourceSize=%d acceptedEvents=%d identities=%d processCharge=%d heapBefore=%d heapAfter=%d delta=%d",
				sourceSize, accepted, accepted*MaxEventSources, processEventSourceBytes.Load(), before, after, int64(after)-int64(before))
			for _, ann := range anns {
				ann.Lock()
				ann.releaseSourceIdentities()
				ann.Event = model.Event{}
				ann.Unlock()
			}
			require.Zero(t, processEventSourceBytes.Load())
			t.Logf("source budget released heap=%d charge=%d", eventBoundsHeap(), processEventSourceBytes.Load())
		})
	}
}
