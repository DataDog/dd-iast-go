package redaction

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/tinylib/msgp/msgp"
)

func TestFXBoundaryVariants(t *testing.T) {
	configureRedaction(t, true, `never-match`, `never-match`)
	previous := config.TruncationMaxValue
	config.TruncationMaxValue = 250
	t.Cleanup(func() { config.TruncationMaxValue = previous })

	cases := []struct{ name, prefix, source, suffix string }{
		{"tainted_starts_at_250", "SELECT id FROM users ORDER BY " + strings.Repeat(" ", 220), "name", ""},
		{"literal_starts_at_250", "SELECT id FROM users ORDER BY " + strings.Repeat(" ", 216), "name", " LIMIT 10"},
	}
	for _, c := range cases {
		snapshot := compositeSnapshot(t, c.prefix, c.source, c.suffix)
		analysis := AnalyzeSQL(snapshot.Value())
		result, ok := BuildWithSensitive(snapshot, analysis.Sensitive, false)
		if analysis.Status != AnalysisOK || !ok {
			t.Fatalf("%s: analysis=%v ok=%t", c.name, analysis.Status, ok)
		}
		last := result.Parts[len(result.Parts)-1]
		jsonPart, _ := json.Marshal(last)
		mp, err := last.MarshalMsg(nil)
		if err != nil {
			t.Fatal(err)
		}
		var mpJSON strings.Builder
		if _, err := msgp.UnmarshalAsJSON(&mpJSON, mp); err != nil {
			t.Fatal(err)
		}
		fmt.Printf("CASE=%s parts=%d LAST_JSON=%s LAST_MSGPACK_AS_JSON=%s\n", c.name, len(result.Parts), jsonPart, strings.TrimSpace(mpJSON.String()))
		if last.Value == "" && last.Pattern == "" {
			t.Errorf("%s: emitted empty part %s", c.name, jsonPart)
		}
	}
}
