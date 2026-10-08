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

// TestJSONDecoderMoreThanEightDocuments decodes 10 documents of one body
// with 10 decoders.
//
// Plan 9.2: PR #39 bound each reader to the request (PropagateReader) and
// gave each value the document of its decoder as its source. This tree has
// no reader bindings: the body source taints the bytes at Read (plan 4.4).
// Each value has the body source, and the source value is the body copy,
// which contains the document.
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
	serveRequest(t, strings.NewReader(body.String()), func(ctx context.Context, r *http.Request) {
		reader := &oneDocumentReader{reader: r.Body}
		ok := true
		for index, document := range documents {
			reader.remaining = len(document)
			var destination struct {
				Value string `json:"value"`
			}
			err := json.NewDecoder(reader).Decode(&destination)
			source := taint.SourceValue{}
			taint.VisitString(ctx, destination.Value, func(found taint.Range) bool {
				source = found.Source
				return false
			})
			if err != nil || destination.Value != fmt.Sprintf("value-%02d", index) || !taint.IsTaintedString(destination.Value) ||
				source.Origin != taint.OriginHttpRequestBody || !strings.Contains(source.Value, document) {
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

// TestJSONDecoderOversizedThenCleanReader decodes a value that is larger
// than the body copy, then decodes a clean reader with the same decoder.
//
// Plan 9.2: PR #39 did not taint a document larger than 64 KiB. In this
// tree, the bits stay on all the bytes. The part of the value that is in
// the body copy has the body source, and the bytes after the copy are
// foreign (Visit does not show them). The clean value is not tainted.
//
// The value has a unique first byte. Thus the content match finds one
// candidate offset. The bytes of the value after the body copy are 'Z', and
// the body copy has no 'Z': they cannot match by chance.
func TestJSONDecoderOversizedThenCleanReader(t *testing.T) {
	requireWoven(t)
	const prefix = `{"value":"`
	var head strings.Builder
	head.WriteString("#")
	for index := 0; len(prefix)+head.Len() < taintrequest.MaxBodyCopy; index++ {
		fmt.Fprintf(&head, "%05x,", index)
	}
	large := head.String()[:taintrequest.MaxBodyCopy-len(prefix)] + strings.Repeat("Z", 32)
	document := prefix + large + `"}`
	observed := make(chan bool, 1)
	serveRequest(t, strings.NewReader(document), func(ctx context.Context, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		var oversized, clean struct {
			Value string `json:"value"`
		}
		errOversized := decoder.Decode(&oversized)
		var ranges []taint.Range
		taint.VisitString(ctx, oversized.Value, func(found taint.Range) bool {
			ranges = append(ranges, found)
			return true
		})
		*decoder = *json.NewDecoder(strings.NewReader(`{"value":"clean"}`))
		errClean := decoder.Decode(&clean)
		ok := errOversized == nil && errClean == nil && oversized.Value == large &&
			taint.IsTaintedString(oversized.Value) && !taint.IsTaintedString(clean.Value) &&
			len(ranges) == 1 && ranges[0].Start == 0 &&
			ranges[0].Length == uint32(taintrequest.MaxBodyCopy-len(prefix)) &&
			ranges[0].Source.Origin == taint.OriginHttpRequestBody &&
			ranges[0].Source.Value == document[:taintrequest.MaxBodyCopy]
		if !ok {
			t.Errorf("errors=%v/%v tainted=%v/%v ranges=%d", errOversized, errClean,
				taint.IsTaintedString(oversized.Value), taint.IsTaintedString(clean.Value), len(ranges))
			for _, found := range ranges {
				t.Errorf("range start=%d length=%d source=%s/%d", found.Start, found.Length, found.Source.Origin, len(found.Source.Value))
			}
		}
		observed <- ok
	})
	if !<-observed {
		t.Fatal("oversized decoder document lost its taint or retained request provenance")
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
