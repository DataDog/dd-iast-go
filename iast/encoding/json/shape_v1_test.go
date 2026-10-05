// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build !goexperiment.jsonv2

package json

import (
	"testing"

	"github.com/DataDog/dd-iast-go/internal/sourceshape"
	"github.com/stretchr/testify/require"
)

// TestSourceShape checks the symbols of the v1 files of encoding/json that
// the [shared] and [v1] aspects of orchestrion.yml use (plan
// encoding-json-v2, section 6.4).
func TestSourceShape(t *testing.T) {
	pkg, err := sourceshape.Load("encoding/json", variantJSONv2)
	require.NoError(t, err)

	// The targets of the function-body join points, and the arguments and
	// results that the templates use.
	for _, target := range []struct{ receiver, name, signature string }{
		{"", "NewDecoder", "func(io.Reader) *Decoder"},
		{"*Decoder", "Decode", "func(any) error"},
		{"*decodeState", "init", "func([]byte) *decodeState"},
		{"*decodeState", "unmarshal", "func(any) error"},
		{"*decodeState", "valueQuoted", "func() any"},
		{"*decodeState", "literalStore", "func([]byte, reflect.Value, bool) error"},
		{"*decodeState", "readIndex", "func() int"},
	} {
		function := pkg.Func(target.receiver, target.name)
		if function == nil {
			t.Errorf("missing encoding/json instrumentation target %s.%s", target.receiver, target.name)
			continue
		}
		if got := sourceshape.Signature(function.Type); got != target.signature {
			t.Errorf("encoding/json %s.%s has the type %q, want %q", target.receiver, target.name, got, target.signature)
		}
	}

	// The struct-definition anchor decodeState, and the fields that the
	// templates use.
	require.NotNil(t, pkg.Fields("decodeState"), "encoding/json has no struct type decodeState")
	for typeName, want := range map[string]map[string]string{
		"Decoder":     {"r": "io.Reader", "d": "decodeState"},
		"decodeState": {"data": "[]byte"},
	} {
		fields := pkg.Fields(typeName)
		for field, fieldType := range want {
			if got := fields[field]; got != fieldType {
				t.Errorf("encoding/json field %s.%s has the type %q, want %q", typeName, field, got, fieldType)
			}
		}
	}

	// The v1 Decoder reads its reader only with Read (plan section 6.4, the
	// consumers of the Read guard): refill calls dec.r.Read, and no method of
	// the Decoder calls another method of dec.r.
	refill := pkg.Func("*Decoder", "refill")
	require.NotNil(t, refill, "encoding/json has no method (*Decoder).refill")
	require.Contains(t, sourceshape.MethodsCalledOn(refill.Body, sourceshape.ReceiverName(refill)+".r"), "Read")
	for _, function := range pkg.Funcs() {
		if sourceshape.Receiver(function) != "*Decoder" || function.Body == nil {
			continue
		}
		for _, method := range sourceshape.MethodsCalledOn(function.Body, sourceshape.ReceiverName(function)+".r") {
			if method != "Read" {
				t.Errorf("(*Decoder).%s calls the method %s of the reader, want only Read", function.Name.Name, method)
			}
		}
	}
}
