package propagation_test

import (
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/taint"
)

// Calling String() repeatedly on an UNCHANGED tracked builder publishes one new
// cloned root per call; the request's 512-root budget is exhausted and every
// later result (and any other new root in the request) is dropped.
func TestReviewRepeatedBuilderStringBurnsRootBudget(t *testing.T) {
	tainted := activeString(t, "attacker")
	var b strings.Builder
	propagation.BuilderWriteString(&b, tainted)
	firstClean := -1
	for i := 0; i < 700; i++ {
		if !taint.IsTaintedString(propagation.BuilderString(&b)) && firstClean < 0 {
			firstClean = i
		}
	}
	t.Logf("unchanged builder: first untainted String() result at call #%d of 700", firstClean)
	if firstClean >= 0 {
		t.Errorf("BUG: repeated String() on an unchanged builder exhausted the request root budget at call %d", firstClean)
	}
}
