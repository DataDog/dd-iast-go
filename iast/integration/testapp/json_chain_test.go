// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
	"github.com/DataDog/dd-iast-go/taint"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPBodyReaderJSONWriterToSQL(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	const document = `{"first":"same","second":"same","escaped":"caf\u00e9","quoted":"\"customers\""}`
	source := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestBody},
		Value:  document,
	}
	type readerState struct {
		active  *store.Store
		readers []io.Reader
	}
	completed := make(chan readerState, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	incoming, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://iast.test/", strings.NewReader(document))
	require.NoError(t, err)

	event := captureRequestEvent(t, func(ctx context.Context, r *http.Request) {
		chain, err := testapp.BuildJSONChain(r.Body)
		completed <- readerState{active: request.ActiveStore(), readers: chain.Readers}
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, testapp.JSONChainDocument{
			First: "same", Second: "same", Escaped: "caf\u00e9", Quoted: "customers",
		}, chain.Document)
		for _, value := range []string{
			string(chain.Document.First), chain.Document.Second, chain.Document.Escaped, string(chain.Document.Quoted),
		} {
			assertChainRanges(t, value, []taint.Range{{Length: uint32(len(value)), Source: source}})
		}
		assert.Equal(t, "SELECT id FROM customers", chain.Query)
		assertChainRanges(t, chain.Query, []taint.Range{{Start: 15, Length: 9, Source: source}})
		var refs [store.MaxSnapshotOwners]store.OwnerRef
		for _, reader := range chain.Readers {
			assert.Equal(t, 1, request.LookupObject(reader, store.BindingReader, refs[:]))
		}
		_, err = db.ExecContext(ctx, chain.Query)
		assert.NoError(t, err)
	}, incoming)

	require.Len(t, event.Vulnerabilities, 1)
	assert.Equal(t, constants.VulnerabilityTypeSqlInjection, event.Vulnerabilities[0].Type)
	assert.Equal(t, []model.Source{
		model.NewSourceString(constants.OriginHttpRequestBody, "", document),
	}, event.Sources)
	assert.Equal(t, model.NewEvidenceTaintedValue([]model.ValuePart{
		model.NewValuePartString("SELECT id FROM "),
		model.NewValuePartTaintedString("customers", 0, nil),
	}), event.Vulnerabilities[0].Evidence)

	select {
	case state := <-completed:
		require.NotNil(t, state.active)
		require.Len(t, state.readers, 4)
		var refs [store.MaxSnapshotOwners]store.OwnerRef
		for _, reader := range state.readers {
			assert.Zero(t, store.LookupObjectValue(state.active, reader, store.BindingReader, refs[:]))
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
