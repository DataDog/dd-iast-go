// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package overhead_test

import (
	"bytes"
	"context"
	"crypto/des"
	"crypto/md5"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DataDog/dd-trace-go/v2/ddtrace/mocktracer"
)

var (
	resultInt     atomic.Int64
	resultString  string
	resultStrings []string
	md5Result     [md5.Size]byte
	sha1Result    [sha1.Size]byte
	desResult     any
)

func BenchmarkBytesClone(b *testing.B) {
	value := []byte("representative-value")
	b.ReportAllocs()
	for b.Loop() {
		resultInt.Store(int64(len(bytes.Clone(value))))
	}
}

func BenchmarkBytesTrimSpace(b *testing.B) {
	value := []byte("representative-value")
	b.ReportAllocs()
	for b.Loop() {
		resultInt.Store(int64(len(bytes.TrimSpace(value))))
	}
}

func BenchmarkBytesSplit(b *testing.B) {
	value := []byte("alpha,beta,gamma")
	b.ReportAllocs()
	for b.Loop() {
		resultInt.Store(int64(len(bytes.Split(value, []byte(",")))))
	}
}

func BenchmarkBytesJoin(b *testing.B) {
	elements := [][]byte{[]byte("alpha"), []byte("beta"), []byte("gamma")}
	b.ReportAllocs()
	for b.Loop() {
		resultInt.Store(int64(len(bytes.Join(elements, []byte(",")))))
	}
}

func BenchmarkBytesRepeat(b *testing.B) {
	value := []byte("alpha")
	b.ReportAllocs()
	for b.Loop() {
		resultInt.Store(int64(len(bytes.Repeat(value, 3))))
	}
}

func BenchmarkBytesReplaceAll(b *testing.B) {
	value := []byte("alpha-beta-alpha")
	b.ReportAllocs()
	for b.Loop() {
		resultInt.Store(int64(len(bytes.ReplaceAll(value, []byte("alpha"), []byte("gamma")))))
	}
}

func BenchmarkBytesToLower(b *testing.B) {
	value := []byte("Attack Value")
	b.ReportAllocs()
	for b.Loop() {
		resultInt.Store(int64(len(bytes.ToLower(value))))
	}
}

func BenchmarkBytesMap(b *testing.B) {
	value := []byte("Attack Value")
	b.ReportAllocs()
	for b.Loop() {
		resultInt.Store(int64(len(bytes.Map(func(r rune) rune { return r + 1 }, value))))
	}
}

func BenchmarkStringsClone(b *testing.B) {
	const value = "representative-value"
	b.ReportAllocs()
	for b.Loop() {
		resultString = strings.Clone(value)
	}
}

func BenchmarkStringsTrimSpace(b *testing.B) {
	const value = "representative-value"
	b.ReportAllocs()
	for b.Loop() {
		resultString = strings.TrimSpace(value)
	}
}

func BenchmarkStringsToLower(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		resultString = strings.ToLower("Attack Value")
	}
}

func BenchmarkFmtSprintf(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		resultString = fmt.Sprintf("value=%s", "attack")
	}
}

func BenchmarkURLQueryEscape(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		resultString = url.QueryEscape("Attack Value")
	}
}

func BenchmarkStrconvQuote(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		resultString = strconv.Quote("Attack Value")
	}
}

func BenchmarkStringsJoin(b *testing.B) {
	elements := []string{"alpha", "beta", "gamma"}
	b.ReportAllocs()
	for b.Loop() {
		resultString = strings.Join(elements, ",")
	}
}

func BenchmarkStringsRepeat(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		resultString = strings.Repeat("alpha", 3)
	}
}

func BenchmarkStringsReplaceAll(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		resultString = strings.ReplaceAll("alpha-beta-alpha", "alpha", "gamma")
	}
}

func BenchmarkStringsSplitSeq(b *testing.B) {
	const value = "alpha,beta,gamma"
	b.ReportAllocs()
	for b.Loop() {
		length := 0
		for part := range strings.SplitSeq(value, ",") {
			length += len(part)
		}
		resultInt.Store(int64(length))
	}
}

func BenchmarkStringsSplit(b *testing.B) {
	const value = "alpha,beta,gamma"
	b.ReportAllocs()
	for b.Loop() {
		resultStrings = strings.Split(value, ",")
	}
}

func BenchmarkHealth(b *testing.B) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	b.ReportAllocs()
	for b.Loop() {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", nil))
		resultInt.Store(int64(recorder.Body.Len()))
	}
}

func BenchmarkRequestProcessing(b *testing.B) {
	handler := requestHandler()
	body := url.Values{"name": {"Ada Lovelace"}, "role": {"engineer"}}.Encode()

	b.ReportAllocs()
	for b.Loop() {
		req := httptest.NewRequest(http.MethodPost, "/profile?id=1843&format=json", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Request-ID", "benchmark-request")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		resultInt.Store(int64(recorder.Body.Len()))
	}
}

func BenchmarkRequestProcessingParallel(b *testing.B) {
	handler := requestHandler()
	body := url.Values{"name": {"Ada Lovelace"}, "role": {"engineer"}}.Encode()

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodPost, "/profile?id=1843&format=json", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Request-ID", "benchmark-request")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			resultInt.Store(int64(recorder.Body.Len()))
		}
	})
}

func BenchmarkHTTPRoundTrip(b *testing.B) {
	body := url.Values{"name": {"Ada Lovelace"}, "role": {"engineer"}}.Encode()
	server := httptest.NewServer(requestHandler())
	b.Cleanup(server.Close)
	client := server.Client()
	mt := mocktracer.Start()
	b.Cleanup(mt.Stop)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/profile?id=1843&format=json", strings.NewReader(body))
		if err != nil {
			b.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Request-ID", "benchmark-request")
		response, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			response.Body.Close()
			b.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			b.Fatal(err)
		}
		mt.Reset()
	}
}

func BenchmarkWeakHashNoActiveSpan(b *testing.B) {
	payload := []byte("representative request payload")

	b.ReportAllocs()
	for b.Loop() {
		md5Result = md5.Sum(payload) //nolint:gosec // Intentionally weak: this benchmarks the IAST sink.
	}
}

func BenchmarkWeakHashActiveSpan(b *testing.B) {
	payload := []byte("representative request payload")
	mt := mocktracer.Start()
	b.Cleanup(mt.Stop)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		//dd:span span.name:benchmark.request
		func(context.Context) {
			sha1Result = sha1.Sum(payload) //nolint:gosec // Intentionally weak: this benchmarks the IAST sink.
		}(context.Background())
		// The mock tracer retains finished spans. Reset on every operation to keep
		// retained memory bounded independently of b.N.
		mt.Reset()
	}
}

func BenchmarkWeakCipherNoActiveSpan(b *testing.B) {
	key := []byte("12345678")

	b.ReportAllocs()
	for b.Loop() {
		block, err := des.NewCipher(key) //nolint:gosec // Intentionally weak: this benchmarks the IAST sink.
		if err != nil {
			b.Fatal(err)
		}
		desResult = block
	}
}

func BenchmarkWeakCipherActiveSpan(b *testing.B) {
	key := []byte("12345678")
	mt := mocktracer.Start()
	b.Cleanup(mt.Stop)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		//dd:span span.name:benchmark.request
		func(context.Context) {
			block, err := des.NewCipher(key) //nolint:gosec // Intentionally weak: this benchmarks the IAST sink.
			if err != nil {
				b.Fatal(err)
			}
			desResult = block
		}(context.Background())
		mt.Reset()
	}
}

func requestHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		response := struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Role      string `json:"role"`
			RequestID string `json:"request_id"`
		}{
			ID:        strings.TrimSpace(req.FormValue("id")),
			Name:      strings.ToUpper(strings.TrimSpace(req.FormValue("name"))),
			Role:      strings.ToLower(strings.TrimSpace(req.FormValue("role"))),
			RequestID: req.Header.Get("X-Request-ID"),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})
}
