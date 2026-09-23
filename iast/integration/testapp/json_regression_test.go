// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	taintrequest "github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
)

func TestJSONDecoderReinitializedWithCleanReader(t *testing.T) {
	requireWoven(t)
	observed := make(chan bool, 1)
	serveRequest(t, strings.NewReader(`{"value":"tainted"}`), func(_ context.Context, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var tainted, clean struct {
			Value string `json:"value"`
		}
		errTainted := decoder.Decode(&tainted)
		*decoder = *json.NewDecoder(strings.NewReader(`{"value":"clean"}`))
		errClean := decoder.Decode(&clean)
		observed <- errTainted == nil && errClean == nil && taint.IsTaintedString(tainted.Value) && !taint.IsTaintedString(clean.Value)
	})
	if !<-observed {
		t.Fatal("reinitialized decoder propagated stale request provenance to a clean reader")
	}
}

func TestJSONUnmarshalPropagatesNestedNamedStringTag(t *testing.T) {
	requireWoven(t)
	observed := make(chan bool, 1)
	serveRequest(t, strings.NewReader(""), func(ctx context.Context, _ *http.Request) {
		type named string
		var destination struct {
			Nested struct {
				Value named `json:"value,string"`
			} `json:"nested"`
		}
		document := taint.TaintBytes(ctx, taint.Source{Origin: constants.OriginHttpRequestBody}, []byte(`{"nested":{"value":"\"secret\""}}`))
		err := json.Unmarshal(document, &destination)
		observed <- err == nil && destination.Nested.Value == "secret" && taint.IsTaintedString(string(destination.Nested.Value))
	})
	if !<-observed {
		t.Fatal("json.Unmarshal did not propagate a nested named string decoded through ,string")
	}
}

func TestJSONDecoderMoreThanEightDocuments(t *testing.T) {
	requireWoven(t)
	const count = 10
	documents := make([]string, count)
	var body strings.Builder
	for index := range count {
		documents[index] = fmt.Sprintf(`{"value":"value-%02d"}`, index)
		body.WriteString(documents[index])
	}
	observed := make(chan bool, 1)
	serveRequest(t, strings.NewReader(body.String()), func(_ context.Context, r *http.Request) {
		reader := &oneDocumentReader{reader: r.Body}
		taintrequest.PropagateReader(r.Body, reader)
		ok := true
		for index, document := range documents {
			reader.remaining = len(document)
			var destination struct {
				Value string `json:"value"`
			}
			err := json.NewDecoder(reader).Decode(&destination)
			source := ""
			taint.VisitString(destination.Value, func(found taint.Range) bool {
				source = found.Source.Value
				return false
			})
			if err != nil || destination.Value != fmt.Sprintf("value-%02d", index) || !taint.IsTaintedString(destination.Value) || source != document {
				t.Errorf("document %d value=%q source=%q tainted=%v error=%v", index, destination.Value, source, taint.IsTaintedString(destination.Value), err)
				ok = false
			}
		}
		observed <- ok
	})
	if !<-observed {
		t.Fatal("distinct decoders exhausted owner-bound reader propagation")
	}
}

func TestJSONDecoderFailureThenCleanReader(t *testing.T) {
	requireWoven(t)
	observed := make(chan bool, 1)
	serveRequest(t, strings.NewReader(`{"value":`), func(_ context.Context, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var failed, clean struct {
			Value string `json:"value"`
		}
		errFailed := decoder.Decode(&failed)
		*decoder = *json.NewDecoder(strings.NewReader(`{"value":"clean"}`))
		errClean := decoder.Decode(&clean)
		observed <- errFailed != nil && errClean == nil && !taint.IsTaintedString(clean.Value)
	})
	if !<-observed {
		t.Fatal("failed decode retained request provenance for a clean reader")
	}
}

func TestJSONDecoderPanicThenCleanReader(t *testing.T) {
	requireWoven(t)
	observed := make(chan bool, 1)
	serveRequest(t, strings.NewReader(`{"value":"panic"}`), func(_ context.Context, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		recovered := decodeJSONPanic(decoder)
		*decoder = *json.NewDecoder(strings.NewReader(`{"value":"clean"}`))
		var clean struct {
			Value string `json:"value"`
		}
		err := decoder.Decode(&clean)
		observed <- recovered == "json panic" && err == nil && !taint.IsTaintedString(clean.Value)
	})
	if !<-observed {
		t.Fatal("panicking decode changed the panic or retained request provenance")
	}
}

func TestJSONDecoderOversizedThenCleanReader(t *testing.T) {
	requireWoven(t)
	large := strings.Repeat("x", store.MaxRootBytes+1)
	observed := make(chan bool, 1)
	serveRequest(t, strings.NewReader(`{"value":"`+large+`"}`), func(_ context.Context, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var oversized, clean struct {
			Value string `json:"value"`
		}
		errOversized := decoder.Decode(&oversized)
		*decoder = *json.NewDecoder(strings.NewReader(`{"value":"clean"}`))
		errClean := decoder.Decode(&clean)
		observed <- errOversized == nil && errClean == nil && oversized.Value == large && !taint.IsTaintedString(oversized.Value) && !taint.IsTaintedString(clean.Value)
	})
	if !<-observed {
		t.Fatal("oversized decoder document published or retained request provenance")
	}
}

func TestJSONUnmarshalStringTagsInNestedAndMapValues(t *testing.T) {
	requireWoven(t)
	observed := make(chan bool, 1)
	serveRequest(t, strings.NewReader(""), func(ctx context.Context, _ *http.Request) {
		type named string
		type item struct {
			Value named `json:"value,string"`
		}
		var destination struct {
			Nested  item            `json:"nested"`
			Mapping map[string]item `json:"mapping"`
		}
		document := taint.TaintBytes(ctx, taint.Source{Origin: constants.OriginHttpRequestBody}, []byte(`{"nested":{"value":"\"same\""},"mapping":{"key":{"value":"\"same\""}}}`))
		err := json.Unmarshal(document, &destination)
		mapped := destination.Mapping["key"].Value
		observed <- err == nil && destination.Nested.Value == "same" && mapped == "same" && taint.IsTaintedString(string(destination.Nested.Value)) && taint.IsTaintedString(string(mapped))
	})
	if !<-observed {
		t.Fatal("json.Unmarshal did not propagate repeated ,string tokens in nested and map values")
	}
}

func TestJSONStringTagLeavesUnchangedValuesUntainted(t *testing.T) {
	requireWoven(t)
	for _, test := range []struct {
		name      string
		document  string
		wantError bool
	}{
		{name: "null", document: `{"value":"null"}`},
		{name: "number", document: `{"value":"123"}`, wantError: true},
		{name: "boolean", document: `{"value":"true"}`, wantError: true},
	} {
		for _, decoder := range []bool{false, true} {
			mode := "unmarshal"
			if decoder {
				mode = "decoder"
			}
			t.Run(test.name+"/"+mode, func(t *testing.T) {
				observed := make(chan bool, 1)
				serveRequest(t, strings.NewReader(test.document), func(ctx context.Context, r *http.Request) {
					destination := struct {
						Value string `json:"value,string"`
					}{Value: "unchanged"}
					var err error
					if decoder {
						err = json.NewDecoder(r.Body).Decode(&destination)
					} else {
						document := taint.TaintBytes(ctx, taint.Source{Origin: constants.OriginHttpRequestBody}, []byte(test.document))
						err = json.Unmarshal(document, &destination)
					}
					observed <- (err != nil) == test.wantError && destination.Value == "unchanged" && !taint.IsTaintedString(destination.Value)
				})
				if !<-observed {
					t.Fatal("a non-string token changed the destination or added request provenance")
				}
			})
		}
	}
}

type oneDocumentReader struct {
	reader    io.Reader
	remaining int
}

func (reader *oneDocumentReader) Read(destination []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	if len(destination) > reader.remaining {
		destination = destination[:reader.remaining]
	}
	read, err := reader.reader.Read(destination)
	reader.remaining -= read
	return read, err
}

func decodeJSONPanic(decoder *json.Decoder) (recovered any) {
	defer func() { recovered = recover() }()
	var destination struct {
		Value panicString `json:"value"`
	}
	_ = decoder.Decode(&destination)
	return nil
}
