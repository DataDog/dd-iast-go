package request

import (
	"context"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

func TestFX_NULDelimiters_in_FormValue_create_a_full_probe_chain(t *testing.T) {
	// Given: a live analysis and 256 query fields whose name/value boundary
	// moves across one shared byte stream containing encoded NULs.
	manager := NewManager(nil)
	analysis, ok := manager.Acquire(1)
	if !ok {
		t.Fatal("cannot acquire request analysis")
	}
	defer analysis.Finish()
	ctx := context.WithValue(context.Background(), contextKey{}, &Scope{
		analysis: analysis,
		decision: DecisionActive,
	})

	stream := "q" + strings.Repeat("\x00r", MaxSources) + "tail"
	params := make(url.Values, MaxSources)
	names := make([]string, MaxSources)
	values := make([]string, MaxSources)
	for i := range MaxSources {
		boundary := 1 + 2*i
		names[i], values[i] = stream[:boundary], stream[boundary+1:]
		params.Set(names[i], values[i])
	}
	req := httptest.NewRequest("GET", "/?"+params.Encode(), nil).WithContext(ctx)
	if err := req.ParseForm(); err != nil {
		t.Fatalf("parse NUL-bearing query: %v", err)
	}
	if len(req.Form) != MaxSources {
		t.Fatalf("parsed %d query fields, want %d", len(req.Form), MaxSources)
	}

	// When: the parsed form map passes through its bounded hook, then the
	// test explicitly invokes the lazy hook after each FormValue call.
	_, _ = ManageForm(ctx, req.Form, req.PostForm)
	if got := analysis.SourceCount(); got != 0 {
		t.Fatalf("map hook admitted %d sources despite its 48-name limit", got)
	}

	table := &analysis.slot.table
	var home uint32
	totalProbes, maxProbes := 0, 0
	for i, name := range names {
		got := req.FormValue(name)
		if got != values[i] {
			t.Fatalf("FormValue(%q) returned a different value", name)
		}
		if managed := ManageParameter(ctx, name, got); managed != got {
			t.Fatalf("parameter %d changed its application-visible value", i)
		}

		currentHome := table.hash(constants.OriginHttpRequestParameter, name, got)
		if i == 0 {
			home = currentHome
		} else if currentHome != home {
			t.Fatalf("tuple %d hashes to slot %d; first tuple hashes to %d", i, currentHome, home)
		}
		probes := 0
		found := false
		for probe := 0; probe < indexSlots; probe++ {
			slot := (home + uint32(probe)) & indexMask
			if table.index[slot] == uint16(i+1) {
				probes = probe + 1
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("source %d is absent from its probe chain", i)
		}
		totalProbes += probes
		if probes > maxProbes {
			maxProbes = probes
		}
	}

	if got := analysis.SourceCount(); got != MaxSources {
		t.Fatalf("FormValue admitted %d sources, want %d", got, MaxSources)
	}
	t.Logf("parsed fields=%d; ManageParameter callbacks=%d; common home slot=%d; final insertion probes=%d; total insertion probes=%d",
		len(req.Form), analysis.SourceCount(), home, maxProbes, totalProbes)
}
