// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp_test

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/taint"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPTransformedCommandReportsOnlyOnAttempt(t *testing.T) {
	requireWoven(t)
	source := taint.SourceValue{
		Source: taint.Source{Origin: taint.OriginHttpRequestParameter, Name: "path"},
		Value:  "  /definitely-not-present-dd-iast  ",
	}
	for _, attempt := range []bool{false, true} {
		name := "construction"
		if attempt {
			name = "attempt"
		}
		t.Run(name, func(t *testing.T) {
			event := requestEvent(t, func(ctx context.Context, r *http.Request) {
				chain := testapp.BuildCommandChain(r.URL.Query().Get("path"))
				assert.Equal(t, "/definitely-not-present-dd-iast", chain.Trimmed)
				assertChainRanges(t, chain.Trimmed, []taint.Range{{Length: 31, Source: source}})
				assert.Equal(t, "/definitely-missing-dd-iast", chain.Replaced)
				expected := []taint.Range{
					{Length: 12, Source: source},
					{Start: 19, Length: 8, Source: source},
				}
				assertChainRanges(t, chain.Replaced, expected)
				assert.Equal(t, "/definitely-missing-dd-iast-chain", chain.Path)
				assertChainRanges(t, chain.Path, expected)
				command := exec.CommandContext(ctx, chain.Path)
				if attempt {
					assert.ErrorIs(t, command.Run(), os.ErrNotExist)
				}
			}, url.Values{"path": {source.Value}})

			if !attempt {
				assert.Empty(t, event.Vulnerabilities)
				assert.Empty(t, event.Sources)
				return
			}
			require.Len(t, event.Vulnerabilities, 1)
			assert.Equal(t, constants.VulnerabilityTypeCommandInjection, event.Vulnerabilities[0].Type)
			assert.Equal(t, []model.Source{
				model.NewSourceString(constants.OriginHttpRequestParameter, "path", source.Value),
			}, event.Sources)
			assert.Equal(t, model.NewEvidenceTaintedValue([]model.ValuePart{
				model.NewValuePartTaintedString("/definitely-", 0, nil),
				model.NewValuePartString("missing"),
				model.NewValuePartTaintedString("-dd-iast", 0, nil),
				model.NewValuePartString("-chain"),
			}), event.Vulnerabilities[0].Evidence)
		})
	}
}
