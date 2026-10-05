// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package json

import (
	"context"
	"errors"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/stretchr/testify/require"
)

// notPropagationPoints are the aspects that change code of encoding/json or
// encoding/json/v2 on a variant, but that move no taint on that variant. The
// key is the aspect id, the value is the variant tag.
var notPropagationPoints = map[string]string{
	// Only the v1 init sets the dispatch variables of this aspect.
	"[shared] encoding/json Decoder reader binding": "[v2]",
	// The guard keeps strings out of the string cache. It propagates nothing.
	"[v2] encoding/json/v2 string cache guard": "[v2]",
}

// aspectTags are the variant tags of the aspect ids of orchestrion.yml.
var aspectTags = []string{"[v1]", "[v2]", "[shared]"}

// jsonAspect is one aspect of orchestrion.yml.
type jsonAspect struct {
	id          string
	importPaths []string
}

// readJSONAspects returns the aspects of orchestrion.yml, with the values of
// their import-path join point clauses.
func readJSONAspects(t *testing.T) []jsonAspect {
	t.Helper()
	contents, err := os.ReadFile("orchestrion.yml")
	require.NoError(t, err)
	var aspects []jsonAspect
	for line := range strings.SplitSeq(string(contents), "\n") {
		if id, ok := strings.CutPrefix(line, "  - id: "); ok {
			aspects = append(aspects, jsonAspect{id: strings.Trim(id, `"`)})
			continue
		}
		trimmed := strings.TrimSpace(line)
		if path, ok := strings.CutPrefix(trimmed, "- import-path: "); ok && len(aspects) > 0 {
			last := &aspects[len(aspects)-1]
			last.importPaths = append(last.importPaths, path)
		}
	}
	require.NotEmpty(t, aspects)
	return aspects
}

func TestInstrumentedPropagationTelemetry(t *testing.T) {
	registered := 0
	seen := map[string]bool{}
	for _, aspect := range readJSONAspects(t) {
		tag, _, _ := strings.Cut(aspect.id, " ")
		require.Contains(t, aspectTags, tag, "aspect %q has no variant tag", aspect.id)
		require.False(t, seen[aspect.id], "aspect %q is not unique", aspect.id)
		seen[aspect.id] = true
		changesJSON := slices.ContainsFunc(aspect.importPaths, func(path string) bool {
			return path == "encoding/json" || path == "encoding/json/v2"
		})
		if !changesJSON || (tag != variantTag && tag != "[shared]") || notPropagationPoints[aspect.id] == variantTag {
			continue
		}
		registered++
	}
	for id := range notPropagationPoints {
		require.True(t, seen[id], "notPropagationPoints has the unknown aspect %q", id)
	}
	require.Equal(t, instrumentedPropagationPoints, registered)
	require.GreaterOrEqual(t, telemetry.InstrumentedPropagation, uint(registered))
}

type customJSONString string

func (*customJSONString) UnmarshalJSON([]byte) error { return nil }

func TestPropagateLiteral(t *testing.T) {
	oldEnabled, oldSampling, oldMax := config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests
	config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = true, 100, 64
	t.Cleanup(func() {
		config.Enabled, config.RequestSamplingPct, config.MaxConcurrentRequests = oldEnabled, oldSampling, oldMax
	})
	ctx, scope, created := request.Begin(context.Background())
	require.True(t, created)
	t.Cleanup(scope.Finish)

	document := taint.TaintBytes(ctx, taint.Source{Origin: constants.OriginHttpRequestBody}, []byte(`{"value":"attack"}`))
	literal := document[9:17]
	destination := "attack"
	propagateLiteral(document, literal, reflect.ValueOf(&destination).Elem(), nil)
	require.Equal(t, "attack", destination)
	require.True(t, taint.IsTaintedString(destination))

	type named string
	outerDocument := taint.TaintBytes(ctx, taint.Source{Origin: constants.OriginHttpRequestBody}, []byte(`{"value":"\"attack\""}`))
	outer := outerDocument[9:21]
	typed := named("attack")
	propagateLiteral(outerDocument, outer, reflect.ValueOf(&typed).Elem(), nil)
	require.Equal(t, named("attack"), typed)
	require.True(t, taint.IsTaintedString(string(typed)))

	custom := customJSONString("unchanged")
	propagateLiteral(document, literal, reflect.ValueOf(&custom).Elem(), nil)
	require.Equal(t, customJSONString("unchanged"), custom)
}

func TestPropagateLiteralRejectsInvalidResults(t *testing.T) {
	document := []byte(`{"value":"clean"}`)
	literal := document[9:16]
	for name, test := range map[string]struct {
		item  []byte
		value reflect.Value
		err   error
	}{
		"decode error":     {item: literal, value: reflect.ValueOf(new(string)).Elem(), err: errors.New("decode failed")},
		"unquoted literal": {item: []byte("null"), value: reflect.ValueOf(new(string)).Elem()},
		"invalid value":    {item: literal},
		"wrong kind":       {item: literal, value: reflect.ValueOf(new(int)).Elem()},
		"unsettable value": {item: literal, value: reflect.ValueOf("clean")},
	} {
		t.Run(name, func(t *testing.T) {
			propagateLiteral(document, test.item, test.value, test.err)
		})
	}
}

func BenchmarkLiteralInactive(b *testing.B) {
	var destination string
	value := reflect.ValueOf(&destination).Elem()
	document := []byte(`{"value":"clean"}`)
	item := document[9:16]
	b.ReportAllocs()
	for b.Loop() {
		propagateLiteral(document, item, value, nil)
	}
}

func BenchmarkLiteralActiveClean(b *testing.B) {
	config.Enabled = true
	config.RequestSamplingPct = 100
	config.MaxConcurrentRequests = 64
	config.VulnerabilitiesPerRequest = 64
	config.RedactionNamePattern = regexp.MustCompile(`never`)
	config.RedactionValuePattern = regexp.MustCompile(`never`)
	ctx, scope, created := request.Begin(context.Background())
	if !created {
		b.Fatal("scope not created")
	}
	defer request.FinishContext(ctx, true)
	var destination string
	value := reflect.ValueOf(&destination).Elem()
	document := []byte(`{"value":"clean"}`)
	item := document[9:16]
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		propagateLiteral(document, item, value, nil)
	}
	_ = scope
}
