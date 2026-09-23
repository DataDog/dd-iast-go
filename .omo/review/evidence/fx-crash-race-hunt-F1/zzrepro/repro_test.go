package fxrepro

// fx-crash-race-hunt-F1 independent reproducer.
// A customer module that enables ONLY the dd-iast-go net/http integration.
// No tracer, no IAST startup, and no server: the request form is parsed once,
// then one goroutine re-calls ParseForm (a no-op in plain Go on a parsed
// request) while another reads r.Form / r.PostForm directly (plain map index,
// no advised accessor involved).

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DataDog/orchestrion/runtime/built"
)

func TestFxParseFormReparseRace(t *testing.T) {
	t.Logf("woven=%v", built.WithOrchestrion)
	r := httptest.NewRequest(http.MethodPost, "/?q=1", strings.NewReader("id=x"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	form, post := r.Form, r.PostForm
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = r.ParseForm()
		}
	}()
	var got string
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			got = r.Form["id"][0] + r.PostForm["id"][0]
		}
	}()
	wg.Wait()
	if got != "xx" {
		t.Fatalf("got %q", got)
	}
	// behavioural identity: re-parse must not replace the maps
	if fmt.Sprintf("%p/%p", r.Form, r.PostForm) != fmt.Sprintf("%p/%p", form, post) {
		t.Fatalf("maps changed")
	}
}
