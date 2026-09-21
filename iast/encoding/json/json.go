// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package json propagates request taint through encoding/json decoding.
package json

import (
	"reflect"

	"github.com/DataDog/dd-iast-go/internal/instrumentation/telemetry"
	"github.com/DataDog/dd-iast-go/internal/taint/jsonbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
)

const instrumentedPropagationPoints = 5

func init() {
	telemetry.InstrumentedPropagation += instrumentedPropagationPoints
	jsonbridge.Register(request.CloneReaderBytes, propagateLiteral)
}

// Activate is referenced by executable bootstrap instrumentation so package
// initialization installs the encoding/json callbacks before main starts.
func Activate() {}

type jsonUnmarshaler interface{ UnmarshalJSON([]byte) error }
type textUnmarshaler interface{ UnmarshalText([]byte) error }

var jsonUnmarshalerType = reflect.TypeOf((*jsonUnmarshaler)(nil)).Elem()
var textUnmarshalerType = reflect.TypeOf((*textUnmarshaler)(nil)).Elem()

func propagateLiteral(document, item []byte, value reflect.Value, err error) {
	if err != nil || len(item) < 2 || item[0] != '"' || !value.IsValid() || value.Kind() != reflect.String || !value.CanSet() {
		return
	}
	if value.CanAddr() && (value.Addr().Type().Implements(jsonUnmarshalerType) || value.Addr().Type().Implements(textUnmarshalerType)) {
		return
	}
	if propagated, ok := propagation.JSONString(document, item, value.String()); ok {
		value.SetString(propagated)
	}
}
