// Command fxwriter measures clean bytes.Buffer mutations outside an IAST
// request while woven HTTP handlers hold writer state.
package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/writerbridge"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

const mutations = 40_000

type response struct {
	status int
	err    error
}

func holdOwners(count int, track bool) func() {
	ready := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !request.FromContext(r.Context()).Active() {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if track {
			input := r.URL.Query().Get("q")
			if !taint.IsTaintedString(input) {
				w.WriteHeader(http.StatusUnprocessableEntity)
				return
			}
			var buffer bytes.Buffer
			if _, err := buffer.WriteString(input); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if !taint.IsTaintedString(buffer.String()) {
				w.WriteHeader(http.StatusPreconditionFailed)
				return
			}
		}
		ready <- struct{}{}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	client := server.Client()
	client.Timeout = 4 * time.Minute
	results := make([]<-chan response, 0, count)
	for attempts := 0; len(results) < count && attempts < count*100; attempts++ {
		done := make(chan response, 1)
		go func() {
			reply, err := client.Get(server.URL + "/?q=untrustedvalue")
			if err != nil {
				done <- response{err: err}
				return
			}
			defer reply.Body.Close()
			done <- response{status: reply.StatusCode}
		}()
		select {
		case <-ready:
			results = append(results, done)
		case reply := <-done:
			if reply.err != nil || reply.status != http.StatusTooManyRequests {
				panic(fmt.Sprintf("request not held: status=%d err=%v", reply.status, reply.err))
			}
		}
	}
	if len(results) != count {
		panic(fmt.Sprintf("only %d of %d requests were sampled", len(results), count))
	}
	return func() {
		close(release)
		for _, done := range results {
			reply := <-done
			if reply.err != nil || reply.status != http.StatusNoContent {
				panic(fmt.Sprintf("held request: status=%d err=%v", reply.status, reply.err))
			}
		}
		server.Close()
	}
}

func measure() int64 {
	buffer := bytes.NewBuffer(make([]byte, 0, mutations))
	// Indirect method calls avoid the application-root propagation wrapper.
	// Only the native bytes.Buffer function-body hook sees these clean writes.
	write := buffer.WriteByte
	start := time.Now()
	for range mutations {
		if err := write('x'); err != nil {
			panic(err)
		}
	}
	elapsed := time.Since(start)
	if buffer.Len() != mutations {
		panic("buffer length changed")
	}
	return elapsed.Nanoseconds() / mutations
}

func report(name string, owners int) int64 {
	samples := []int64{measure(), measure(), measure()}
	slices.Sort(samples)
	fmt.Printf("%s owners=%d writerActive=%t ns_per_clean_WriteByte=%d samples=%v\n",
		name, owners, writerbridge.Active(), samples[1], samples)
	return samples[1]
}

func main() {
	owners := 2
	if len(os.Args) > 1 {
		n, err := strconv.Atoi(os.Args[1])
		if err != nil || n < 1 || n > config.MaxConcurrentRequests {
			panic(fmt.Sprintf("expected 1..%d owners", config.MaxConcurrentRequests))
		}
		owners = n
	}
	fmt.Printf("woven=%t sampling=%d maxConcurrent=%d requestedOwners=%d\n",
		built.WithOrchestrion, config.RequestSamplingPct, config.MaxConcurrentRequests, owners)
	baseline := report("no_request", 0)
	stop := holdOwners(1, false)
	report("request_without_writer", 1)
	stop()
	stop = holdOwners(1, true)
	one := report("one_tracked_writer", 1)
	stop()
	stop = holdOwners(owners, true)
	many := report("many_tracked_writers", owners)
	stop()
	recovered := report("after_finish", 0)
	fmt.Printf("ratios one/baseline=%.2f many/baseline=%.2f after/baseline=%.2f\n",
		float64(one)/float64(baseline), float64(many)/float64(baseline), float64(recovered)/float64(baseline))
}
