// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build go1.27 && goexperiment.jsonv2

package testapp_test

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"net/http"
	"testing"

	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/stretchr/testify/assert"
)

// TestJSONV2StreamingAPIsAreMiss checks the documented misses of decision
// Q3: the direct encoding/json/v2 streaming APIs on the request body give
// no taint, and the request reports no finding.
func TestJSONV2StreamingAPIsAreMiss(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	const document = `{"value":"streamed"}`
	for name, decode := range map[string]func(r *http.Request) (string, error){
		"UnmarshalRead": func(r *http.Request) (string, error) {
			var destination jsonValue
			err := jsonv2.UnmarshalRead(r.Body, &destination)
			return destination.Value, err
		},
		"jsontext.Decoder": func(r *http.Request) (string, error) {
			decoder := jsontext.NewDecoder(r.Body)
			for {
				token, err := decoder.ReadToken()
				if err != nil {
					return "", err
				}
				if token.Kind() == '"' && token.String() == "value" {
					value, err := decoder.ReadToken()
					return value.String(), err
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			event := bodyEvent(t, document, func(ctx context.Context, r *http.Request) {
				value, err := decode(r)
				if !assert.NoError(t, err) {
					return
				}
				assert.Equal(t, "streamed", value)
				assertNoTaint(t, value)
				_, err = db.ExecContext(ctx, testapp.BuildTableQuery(value))
				assert.NoError(t, err)
			})
			requireSQLFindings(t, event, 0, "")
		})
	}
}
