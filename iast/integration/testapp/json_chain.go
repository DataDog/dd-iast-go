// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package testapp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
)

// JSONName exercises typed string destinations.
type JSONName string

// JSONChainDocument includes equal literals, escaped text, and a quoted string.
type JSONChainDocument struct {
	First   JSONName `json:"first"`
	Second  string   `json:"second"`
	Escaped string   `json:"escaped"`
	Quoted  JSONName `json:"quoted,string"`
}

// JSONChainValues retains intermediate values and readers for test inspection.
type JSONChainValues struct {
	Document JSONChainDocument
	Readers  []io.Reader
	Query    string
}

// BuildJSONChain composes native readers, JSON decoding, and writer propagation.
func BuildJSONChain(body io.Reader) (JSONChainValues, error) {
	limited := io.LimitReader(body, 4096)
	buffered := bufio.NewReader(limited)
	composed := io.MultiReader(bytes.NewReader(nil), buffered)
	result := JSONChainValues{Readers: []io.Reader{body, limited, buffered, composed}}
	if err := json.NewDecoder(composed).Decode(&result.Document); err != nil {
		return result, err
	}
	var writer bytes.Buffer
	writer.WriteString("SELECT id FROM ")
	writer.WriteString(string(result.Document.Quoted))
	result.Query = writer.String()
	return result, nil
}

// DecodeRepeatedJSON preserves the separate sources of two equal literals.
func DecodeRepeatedJSON(first, second []byte) (JSONChainDocument, error) {
	document := bytes.Join([][]byte{
		[]byte(`{"first":`), first, []byte(`,"second":`), second, []byte(`}`),
	}, nil)
	var result JSONChainDocument
	err := json.Unmarshal(document, &result)
	return result, err
}
