package vulnerability

import (
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/vulnerability/dedup"
)

func TestReproLocationlessHashCollision(t *testing.T) {
	// CaptureLocationSkipWhile returns locationFromTrace(spanID, nil) whenever
	// firstApplicationFrame fails (frame gap, all frames skipped, top/bottom split).
	a := model.NewVulnerability(constants.VulnerabilityTypeSqlInjection, model.NewEvidenceString("SELECT a"), locationFromTrace(111, nil))
	b := model.NewVulnerability(constants.VulnerabilityTypeSqlInjection, model.NewEvidenceString("DELETE b"), locationFromTrace(222, nil))
	t.Logf("location-less hashes: a=%d b=%d equal=%t", a.Hash, b.Hash, a.Hash == b.Hash)
	var set dedup.Set
	now := time.Now()
	set.Add(a.Hash, now)
	t.Logf("process dedup Check(b) after committing a: %v (2 == CheckPresent)", set.Check(b.Hash, now.Add(59*time.Minute)))
}
