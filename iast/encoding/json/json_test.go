// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package json

import (
	"context"
	"errors"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/stretchr/testify/require"
)

func TestInstrumentedPropagationTelemetry(t *testing.T) {
	contents, err := os.ReadFile("orchestrion.yml")
	require.NoError(t, err)
	registered := strings.Count(string(contents), "- import-path: encoding/json")
	require.Equal(t, registered, instrumentedPropagationPoints)
	require.GreaterOrEqual(t, telemetry.InstrumentedPropagation, uint(registered))
}

func TestSourceShape(t *testing.T) {
	directory := filepath.Join(runtime.GOROOT(), "src", "encoding", "json")
	pkg, err := build.ImportDir(directory, 0)
	require.NoError(t, err)
	found := map[string]bool{}
	fields := map[string]string{}
	for _, name := range pkg.GoFiles {
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			if general, ok := declaration.(*ast.GenDecl); ok {
				for _, specification := range general.Specs {
					typeSpec, ok := specification.(*ast.TypeSpec)
					if !ok || (typeSpec.Name.Name != "Decoder" && typeSpec.Name.Name != "decodeState") {
						continue
					}
					structure, ok := typeSpec.Type.(*ast.StructType)
					if !ok {
						continue
					}
					for _, field := range structure.Fields.List {
						for _, name := range field.Names {
							fields[typeSpec.Name.Name+"."+name.Name] = types.ExprString(field.Type)
						}
					}
				}
			}
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
			case "Decoder.Decode", "decodeState.init", "decodeState.literalStore", "decodeState.unmarshal", "decodeState.valueQuoted":
				found[key] = true
			}
		}
	}
	for _, key := range []string{"Decoder.Decode", "decodeState.init", "decodeState.literalStore", "decodeState.unmarshal", "decodeState.valueQuoted"} {
		if !found[key] {
			t.Errorf("missing encoding/json instrumentation target %s", key)
		}
	}
	for key, want := range map[string]string{"Decoder.r": "io.Reader", "Decoder.d": "decodeState", "decodeState.data": "[]byte"} {
		if got := fields[key]; got != want {
			t.Errorf("encoding/json field %s has type %q, want %q", key, got, want)
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
