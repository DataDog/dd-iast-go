// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package json

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/stretchr/testify/require"
)

func TestGo126SourceShape(t *testing.T) {
	if runtime.Version() != "go1.26.6" {
		t.Fatalf("encoding/json aspects require go1.26.6, got %s", runtime.Version())
	}
	files := []string{"decode.go", "stream.go"}
	found := map[string]bool{}
	for _, name := range files {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(runtime.GOROOT(), "src", "encoding", "json", name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv == nil || len(function.Recv.List) != 1 {
				continue
			}
			receiver, ok := function.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			identifier, ok := receiver.X.(*ast.Ident)
			if !ok {
				continue
			}
			key := identifier.Name + "." + function.Name.Name
			switch key {
			case "Decoder.Decode", "decodeState.init", "decodeState.literalStore":
				found[key] = true
			}
		}
	}
	for _, key := range []string{"Decoder.Decode", "decodeState.init", "decodeState.literalStore"} {
		if !found[key] {
			t.Fatalf("missing pinned encoding/json function %s", key)
		}
	}
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
