// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package json

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
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
