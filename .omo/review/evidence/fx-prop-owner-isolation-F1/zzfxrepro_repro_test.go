package zzfxrepro

import (
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// Plain customer code, woven by orchestrion with default IAST configuration
// (DD_IAST_ENABLED default true, sampling 30%, 2 concurrent analyses). The
// handler fires an async audit goroutine that reads the request URL query and
// never joins it, which is valid net/http usage (the Request is not reused).
var audit sync.WaitGroup

func handler(w http.ResponseWriter, r *http.Request) {
	audit.Add(1)
	go func() {
		defer audit.Done()
		_ = len(r.URL.Query()) // async audit log of query parameters
	}()
	sum := sha256.Sum256([]byte(r.URL.Path)) // simulated request work
	for i := 0; i < 200; i++ {
		sum = sha256.Sum256(sum[:])
	}
	_, _ = w.Write(sum[:4])
}

func TestFxWovenDetachedQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()
	client := srv.Client()
	for i := 0; i < 3000; i++ {
		resp, err := client.Get(srv.URL + "/audit")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	audit.Wait()
	t.Logf("requests=3000")
}
