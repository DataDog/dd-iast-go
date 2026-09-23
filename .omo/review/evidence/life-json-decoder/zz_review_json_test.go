package testapp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/jsonbridge"
	taintrequest "github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
)

var reviewDeep = strings.Repeat("[", 5000) + strings.Repeat("]", 5000)

type reviewDoc struct {
	Value string `json:"value"`
	Deep  any    `json:"deep"`
}

// Decoder is a local that does not escape: the compiler may stack-allocate it.
//
//go:noinline
func reviewStackDecode(doc string) error {
	var v reviewDoc
	return json.NewDecoder(strings.NewReader(doc)).Decode(&v)
}

//go:noinline
func reviewStackUnmarshal(doc []byte) error {
	var v reviewDoc
	return json.Unmarshal(doc, &v)
}

func reviewTaintedDecode(t *testing.T, label string) bool {
	t.Helper()
	observed := make(chan bool, 1)
	serveRequest(t, strings.NewReader(`{"value":"tainted"}`), func(_ context.Context, r *http.Request) {
		var v struct {
			Value string `json:"value"`
		}
		err := json.NewDecoder(r.Body).Decode(&v)
		observed <- err == nil && v.Value == "tainted" && taint.IsTaintedString(v.Value)
	})
	ok := <-observed
	count, _, _ := jsonbridge.ReviewOccupied()
	t.Logf("%s: request-body Decoder value tainted=%v occupiedSlots=%d", label, ok, count)
	return ok
}

func TestReviewStackMovedDecodeStateLeaksSlots(t *testing.T) {
	requireWoven(t)
	for _, mode := range []string{"Decoder.Decode", "Unmarshal"} {
		before, _, _ := jsonbridge.ReviewOccupied()
		baseline := reviewTaintedDecode(t, mode+" baseline")
		doc := `{"value":"x","deep":` + reviewDeep + `}`
		serveRequest(t, strings.NewReader(""), func(context.Context, *http.Request) {
			for i := 0; i < 400; i++ {
				done := make(chan error, 1)
				go func() {
					if mode == "Unmarshal" {
						done <- reviewStackUnmarshal([]byte(doc))
					} else {
						done <- reviewStackDecode(doc)
					}
				}()
				if err := <-done; err != nil {
					t.Errorf("decode %d: %v", i, err)
					return
				}
			}
		})
		after, pointers, depths := jsonbridge.ReviewOccupied()
		t.Logf("%s: occupied slots before=%d after 400 completed decodes=%d (no decode is running now)", mode, before, after)
		if len(pointers) > 0 {
			t.Logf("%s: sample leaked slot pointers=%#x depths=%v", mode, pointers[:min(4, len(pointers))], depths[:min(4, len(depths))])
		}
		afterTaint := reviewTaintedDecode(t, mode+" after leaks")
		if after != before || baseline != afterTaint {
			t.Errorf("%s: LEAK: completed decodes left %d slots occupied; request-body taint baseline=%v after=%v", mode, after-before, baseline, afterTaint)
		}
	}
}

type reviewGateReader struct {
	mu      sync.Mutex
	gate    chan struct{}
	waiting atomic.Int32
	next    int
	docs    []string
}

func (r *reviewGateReader) Read(p []byte) (int, error) {
	r.waiting.Add(1)
	<-r.gate
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.next >= len(r.docs) {
		return 0, io.EOF
	}
	n := copy(p, r.docs[r.next])
	r.next++
	return n, nil
}

func TestReviewConcurrentHeapDecodersHashCapacity(t *testing.T) {
	requireWoven(t)
	count := reviewCount()
	offset := reflect.TypeFor[json.Decoder]().Size()
	field, _ := reflect.TypeFor[json.Decoder]().FieldByName("d")
	t.Logf("sizeof(json.Decoder)=%d offset(d)=%d", offset, field.Offset)
	observed := make(chan string, 1)
	serveRequest(t, strings.NewReader("x"), func(_ context.Context, r *http.Request) {
		reader := &reviewGateReader{gate: make(chan struct{})}
		for i := range count {
			reader.docs = append(reader.docs, fmt.Sprintf(`{"value":"v%02d"}`, i))
		}
		taintrequest.PropagateReader(r.Body, reader)
		decoders := make([]*json.Decoder, count)
		buckets := map[uintptr]int{}
		for i := range decoders {
			decoders[i] = json.NewDecoder(reader)
			state := uintptr(unsafe.Pointer(decoders[i])) + field.Offset
			buckets[(state>>3)%64]++
		}
		values := make([]string, count)
		var finished atomic.Int32
		var wg sync.WaitGroup
		for i := range decoders {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var v struct {
					Value string `json:"value"`
				}
				_ = decoders[i].Decode(&v)
				values[i] = v.Value
				finished.Add(1)
			}()
		}
		for reader.waiting.Load() < int32(count) {
			runtimeGosched()
		}
		occupied, _, _ := jsonbridge.ReviewOccupied()
		if os.Getenv("REVIEW_SERIAL") != "" {
			// Release one Read at a time and wait for that Decode to finish.
			for i := 0; i < count; i++ {
				reader.gate <- struct{}{}
				for finished.Load() < int32(i+1) {
					runtimeGosched()
				}
			}
		} else {
			close(reader.gate)
		}
		wg.Wait()
		tainted := 0
		for _, value := range values {
			if taint.IsTaintedString(value) {
				tainted++
			}
		}
		observed <- fmt.Sprintf("decoders=%d distinctStartBuckets=%d buckets=%v occupiedWhileBlocked=%d taintedResults=%d", count, len(buckets), buckets, occupied, tainted)
	})
	result := <-observed
	t.Logf("diag: docNoReader=%d docNoClone=%d docStored=%d litMapped=%d enter=%d noSlot=%d inactive=%d noDoc=%d docMismatch=%d", jsonbridge.ReviewDocNoReader.Load(), jsonbridge.ReviewDocNoClone.Load(), jsonbridge.ReviewDocStored.Load(), jsonbridge.ReviewLitMapped.Load(), jsonbridge.ReviewLitEnter.Load(), jsonbridge.ReviewLitNoSlot.Load(), jsonbridge.ReviewLitInactive.Load(), jsonbridge.ReviewLitNoDoc.Load(), jsonbridge.ReviewLitDocMismatch.Load())
	t.Log(result)
}

func reviewCount() int {
	if value := os.Getenv("REVIEW_COUNT"); value != "" {
		n, _ := strconv.Atoi(value)
		return n
	}
	return 16
}

func reviewSource(value string) string {
	source := ""
	taint.VisitString(value, func(found taint.Range) bool { source = found.Source.Value; return false })
	return source
}

func TestReviewStreamingDecoderMultipleDecodes(t *testing.T) {
	requireWoven(t)
	large := strings.Repeat("x", 70*1024)
	docs := []string{`{"value":"first"}`, `{"value":"` + large + `"}`, `{"value":"third"}`}
	observed := make(chan []string, 1)
	serveRequest(t, strings.NewReader(strings.Join(docs, "\n")), func(_ context.Context, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var out []string
		for range docs {
			var v struct {
				Value string `json:"value"`
			}
			err := decoder.Decode(&v)
			out = append(out, fmt.Sprintf("err=%v len=%d tainted=%v sourceLen=%d", err, len(v.Value), taint.IsTaintedString(v.Value), len(reviewSource(v.Value))))
		}
		observed <- out
	})
	for index, line := range <-observed {
		t.Logf("decode %d (doc len %d): %s", index, len(docs[index]), line)
	}
	count, _, _ := jsonbridge.ReviewOccupied()
	t.Logf("occupied slots after: %d", count)
}

func TestReviewTokenStreamAndPointerFields(t *testing.T) {
	requireWoven(t)
	observed := make(chan []string, 1)
	serveRequest(t, strings.NewReader(`[{"value":"a1","ptr":"p1","any":"i1"},{"value":"a2","ptr":"p2","any":"i2"}]`), func(_ context.Context, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var out []string
		_, err := decoder.Token()
		out = append(out, fmt.Sprintf("open token err=%v", err))
		for decoder.More() {
			var v struct {
				Value string  `json:"value"`
				Ptr   *string `json:"ptr"`
				Any   any     `json:"any"`
			}
			err := decoder.Decode(&v)
			anyString, _ := v.Any.(string)
			out = append(out, fmt.Sprintf("err=%v value=%q tainted=%v source=%q | *string=%q tainted=%v | any=%q tainted=%v", err, v.Value, taint.IsTaintedString(v.Value), reviewSource(v.Value), *v.Ptr, taint.IsTaintedString(*v.Ptr), anyString, taint.IsTaintedString(anyString)))
		}
		observed <- out
	})
	for _, line := range <-observed {
		t.Log(line)
	}
}

type reviewPanicText string

func (*reviewPanicText) UnmarshalJSON([]byte) error { panic("review panic") }

func TestReviewUnmarshalPanicCleanup(t *testing.T) {
	requireWoven(t)
	observed := make(chan string, 1)
	serveRequest(t, strings.NewReader(""), func(ctx context.Context, _ *http.Request) {
		document := taint.TaintBytes(ctx, taint.Source{Origin: constants.OriginHttpRequestBody}, []byte(`{"a":"\"q\"","b":"x"}`))
		recovered := func() (value any) {
			defer func() { value = recover() }()
			var v struct {
				A string          `json:"a,string"`
				B reviewPanicText `json:"b"`
			}
			_ = json.Unmarshal(document, &v)
			return nil
		}()
		count, _, _ := jsonbridge.ReviewOccupied()
		var after struct {
			A string `json:"a,string"`
		}
		err := json.Unmarshal(document, &after)
		observed <- fmt.Sprintf("recovered=%v occupiedAfterPanic=%d nextErr=%v next=%q tainted=%v", recovered, count, err, after.A, taint.IsTaintedString(after.A))
	})
	t.Log(<-observed)
}
