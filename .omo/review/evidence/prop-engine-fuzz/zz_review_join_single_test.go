// Review reproducer (prop-engine-fuzz): strings.Join of one element with a
// non-empty separator returns elems[0] itself; JoinString clones it anyway and
// adopts a second managed root for the same bytes.

package propagation_test

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

func TestReviewJoinSingleElementClones(t *testing.T) {
	s, _ := beginScope(t)
	owner := acquireOwner(t, s)
	value, _ := taintString(t, owner, strings.Repeat("q", 4096), []ranges.Range{{Length: 4096, SourceID: 1}})
	elements := []string{value}
	native := strings.Join(elements, ",")
	t.Logf("native aliases element: %v", unsafe.StringData(native) == unsafe.StringData(value))
	chargedBefore, valuesBefore := owner.Charged(), owner.Values()
	got := propagation.JoinString(elements, ",", native)
	t.Logf("JoinString returned alias: %v", unsafe.StringData(got) == unsafe.StringData(native))
	t.Logf("owner charge: %d -> %d bytes; owner values: %d -> %d", chargedBefore, owner.Charged(), valuesBefore, owner.Values())
	t.Logf("ranges on returned value: %v", lookupRanges(s, got))
	if unsafe.StringData(got) != unsafe.StringData(native) {
		t.Errorf("JoinString replaced an already-tracked alias with a fresh %d-byte clone (extra charge %d bytes)", len(got), owner.Charged()-chargedBefore)
	}
}
