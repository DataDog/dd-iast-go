package testapp_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"unsafe"

	taintrequest "github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

type fxEnterReader struct {
	r       io.Reader
	once    sync.Once
	entered chan struct{}
}

func (e *fxEnterReader) Read(p []byte) (int, error) {
	e.once.Do(func() { close(e.entered) })
	return e.r.Read(p)
}

var fxDecoderStateOffset = func() uintptr {
	f, _ := reflect.TypeFor[json.Decoder]().FieldByName("d")
	return f.Offset
}()

func fxBucket(d *json.Decoder) uintptr {
	return ((uintptr(unsafe.Pointer(d)) + fxDecoderStateOffset) >> 3) % 64
}

// Order: A binds, B binds (same start bucket when collide), A finishes while B blocks in Read, B's body arrives.
func fxRun(t *testing.T, collide bool) (bTainted bool, bBucket uintptr, ok bool) {
	t.Helper()
	aBucketCh := make(chan uintptr, 1)
	bBucketCh := make(chan uintptr, 1)
	aEntered, bEntered := make(chan struct{}), make(chan struct{})
	bResult := make(chan bool, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span, ctx := tracer.StartSpanFromContext(r.Context(), "iast.fx.request")
		defer span.Finish()
		r = r.WithContext(ctx)
		var v struct {
			Value string `json:"value"`
		}
		if r.URL.Path == "/a" {
			reader := &fxEnterReader{r: r.Body, entered: aEntered}
			taintrequest.PropagateReader(r.Body, reader)
			dec := json.NewDecoder(reader)
			aBucketCh <- fxBucket(dec)
			_ = dec.Decode(&v)
		} else {
			target := <-aBucketCh
			reader := &fxEnterReader{r: r.Body, entered: bEntered}
			taintrequest.PropagateReader(r.Body, reader)
			var keep []*json.Decoder
			var dec *json.Decoder
			for i := 0; i < 8192; i++ {
				d := json.NewDecoder(reader)
				keep = append(keep, d)
				same := fxBucket(d) == target
				if same == collide {
					dec = d
					break
				}
			}
			if dec == nil {
				bBucketCh <- 999
				close(bEntered)
				bResult <- false
				w.WriteHeader(http.StatusNoContent)
				return
			}
			bBucketCh <- fxBucket(dec)
			err := dec.Decode(&v)
			bResult <- err == nil && v.Value == "request-b" && taint.IsTaintedString(v.Value)
			_ = keep
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	aBody, aWriter := io.Pipe()
	bBody, bWriter := io.Pipe()
	post := func(path string, body io.Reader, done chan<- error) {
		req, err := http.NewRequest(http.MethodPost, server.URL+path, body)
		if err != nil {
			done <- err
			return
		}
		resp, err := server.Client().Do(req)
		if err == nil {
			resp.Body.Close()
		}
		done <- err
	}
	aDone, bDone := make(chan error, 1), make(chan error, 1)
	go post("/a", aBody, aDone)
	<-aEntered
	go post("/b", bBody, bDone)
	<-bEntered
	bBucket = <-bBucketCh
	fmt.Fprint(aWriter, `{"value":"request-a"}`)
	aWriter.Close()
	if err := <-aDone; err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(bWriter, `{"value":"request-b"}`)
	bWriter.Close()
	bTainted = <-bResult
	if err := <-bDone; err != nil {
		t.Fatal(err)
	}
	return bTainted, bBucket, bBucket != 999
}

func TestFxF1NestedBindConcurrentRequests(t *testing.T) {
	requireWoven(t)
	const iterations = 20
	for _, collide := range []bool{false, true} {
		tainted, valid := 0, 0
		for i := 0; i < iterations; i++ {
			ok, b, v := fxRun(t, collide)
			if !v {
				continue
			}
			valid++
			if ok {
				tainted++
			}
			if i == 0 {
				t.Logf("collide=%v sample: B bucket=%d B value tainted=%v", collide, b, ok)
			}
		}
		t.Logf("collide=%v: request-B Decoder results tainted %d/%d", collide, tainted, valid)
		if collide && tainted != valid {
			t.Errorf("BUG: request-B lost body taint in %d/%d colliding runs (A finished while B blocked in Read)", valid-tainted, valid)
		}
		if !collide && tainted != valid {
			t.Errorf("control: non-colliding runs lost taint %d/%d", valid-tainted, valid)
		}
	}
}
