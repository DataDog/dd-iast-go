// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/taint"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTTPBodyReaderJSONWriterToSQL reads the request body through
// io.LimitReader, bufio.Reader, io.MultiReader and json.Decoder, then writes
// a decoded value into a bytes.Buffer and runs the result as SQL.
//
// Plan 9.2: PR #39 also checked that each reader was bound to the request
// in its store. This tree has no reader bindings (the bits follow the
// bytes), thus these checks are dropped.
func TestHTTPBodyReaderJSONWriterToSQL(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	const document = `{"first":"same","second":"same","escaped":"caf\u00e9","quoted":"\"customers\""}`
	source := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestBody},
		Value:  document,
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	incoming, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://iast.test/", strings.NewReader(document))
	require.NoError(t, err)

	event := captureRequestEvent(t, func(ctx context.Context, r *http.Request) {
		chain, err := testapp.BuildJSONChain(r.Body)
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, chain.Readers, 4)
		assert.Equal(t, testapp.JSONChainDocument{
			First: "same", Second: "same", Escaped: "caf\u00e9", Quoted: "customers",
		}, chain.Document)
		for _, value := range []string{
			string(chain.Document.First), chain.Document.Second, chain.Document.Escaped, string(chain.Document.Quoted),
		} {
			assertChainRanges(t, ctx, value, []taint.Range{{Length: uint32(len(value)), Source: source}})
		}
		assert.Equal(t, "SELECT id FROM customers", chain.Query)
		assertChainRanges(t, ctx, chain.Query, []taint.Range{{Start: 15, Length: 9, Source: source}})
		_, err = db.ExecContext(ctx, chain.Query)
		assert.NoError(t, err)
	}, incoming)

	require.Len(t, event.Vulnerabilities, 1)
	assert.Equal(t, constants.VulnerabilityTypeSqlInjection, event.Vulnerabilities[0].Type)
	assertLocationsInTestFile(t, event, "json_chain_test.go")
	assert.Equal(t, []model.Source{
		model.NewSourceString(constants.OriginHttpRequestBody, "", document),
	}, event.Sources)
	assert.Equal(t, model.NewEvidenceTaintedValue([]model.ValuePart{
		model.NewValuePartString("SELECT id FROM "),
		model.NewValuePartTaintedString("customers", 0, nil),
	}), event.Vulnerabilities[0].Evidence)
}

// TestHTTPLargeJSONBodyFieldAfter4KiBToSQL decodes an 8 KiB JSON body. The
// only value that goes to the sink is the last field, after byte 4096 of
// the body (plan 9.1 item 4). The body is decoded with json.Unmarshal (after
// io.ReadAll) and with json.Decoder. The decoded value goes through a
// bytes.Buffer to the SQL sink.
func TestHTTPLargeJSONBodyFieldAfter4KiBToSQL(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	document := `{"padding":"` + strings.Repeat("p", 8<<10) + `","table":"customers"}`
	require.Greater(t, strings.Index(document, `"customers"`), 4096)
	// The SQL source value is the body copy. The truncation of the event
	// makes it shorter.
	wantSource := model.NewSourceString(constants.OriginHttpRequestBody, "", document)

	for _, mode := range []testapp.JSONDecodeMode{testapp.JSONUnmarshal, testapp.JSONDecoder} {
		t.Run(mode.String(), func(t *testing.T) {
			incoming, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://iast.test/", strings.NewReader(document))
			require.NoError(t, err)
			event := captureRequestEvent(t, func(ctx context.Context, r *http.Request) {
				query, err := testapp.BuildLargeJSONQuery(r.Body, mode)
				if !assert.NoError(t, err) {
					return
				}
				assert.Equal(t, "SELECT id FROM customers", query)
				assertChainRanges(t, ctx, query, []taint.Range{{
					Start:  15,
					Length: 9,
					Source: taint.SourceValue{
						Source: taint.Source{Origin: taint.OriginHttpRequestBody},
						Value:  document,
					},
				}})
				_, err = db.ExecContext(ctx, query)
				assert.NoError(t, err)
			}, incoming)

			require.Len(t, event.Vulnerabilities, 1)
			assert.Equal(t, constants.VulnerabilityTypeSqlInjection, event.Vulnerabilities[0].Type)
			assertLocationsInTestFile(t, event, "json_chain_test.go")
			assert.Equal(t, []model.Source{wantSource}, event.Sources)
			assert.Equal(t, model.NewEvidenceTaintedValue([]model.ValuePart{
				model.NewValuePartString("SELECT id FROM "),
				model.NewValuePartTaintedString("customers", 0, nil),
			}), event.Vulnerabilities[0].Evidence)
		})
	}
}
