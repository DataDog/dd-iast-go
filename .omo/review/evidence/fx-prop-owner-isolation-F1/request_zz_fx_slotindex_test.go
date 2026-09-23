package request

import (
	"bytes"
	"context"
	"io"
	"net/url"
	"runtime"
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
)

// fx-prop-owner-isolation-F1: independent reproducer. Each "request" spawns a
// fire-and-forget goroutine (never joined before the request finishes), as a
// customer handler doing async logging would. The goroutine reaches
// analysisForOwner through the lazy URL-query hook or the io.ReadAll hook while
// the owner is live; the request then finishes and the next request reuses the
// permit through Manager.Acquire. Default MaxConcurrentRequests (2) is used.
func fxConfig(t *testing.T) {
	t.Helper()
	pe, ps, pm := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 2
	t.Cleanup(func() { config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = pe, ps, pm })
}

func fxRun(t *testing.T, detached func(u *url.URL, body io.Reader)) {
	fxConfig(t)
	var wg sync.WaitGroup // joined only at test end, never per request
	for cycle := 0; cycle < 2000; cycle++ {
		ctx, scope, created := Begin(context.Background())
		if !created || !scope.Active() {
			t.Fatalf("cycle %d: scope not active", cycle)
		}
		u := &url.URL{Path: "/fx", RawQuery: ""}
		body := io.NopCloser(bytes.NewReader([]byte("payload-body")))
		EagerHTTP(ctx, nil, nil, nil, nil, u, body)
		wg.Add(1)
		go func() { defer wg.Done(); detached(u, body) }()
		for i := 0; i < 16; i++ { // simulated handler work, no synchronization with the goroutine
			runtime.Gosched()
		}
		scope.Finish()
	}
	wg.Wait()
}

func TestFxSlotIndexRaceURLQuery(t *testing.T) {
	fxRun(t, func(u *url.URL, _ io.Reader) { ManageURLQuery(u, u.Query()) })
}

func TestFxSlotIndexRaceReadAll(t *testing.T) {
	fxRun(t, func(_ *url.URL, body io.Reader) { ReadAllBytes(body, []byte("payload-body")) })
}
