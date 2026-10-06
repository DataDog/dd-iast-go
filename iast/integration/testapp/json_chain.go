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
	composed := io.MultiReader(buffered)
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

// DecodeRepeatedJSON decodes a document that has the 2 given literals.
func DecodeRepeatedJSON(first, second []byte) (JSONChainDocument, error) {
	document := bytes.Join([][]byte{
		[]byte(`{"first":`), first, []byte(`,"second":`), second, []byte(`}`),
	}, nil)
	var result JSONChainDocument
	err := json.Unmarshal(document, &result)
	return result, err
}

// JSONDecodeMode selects the encoding/json API of BuildLargeJSONQuery.
type JSONDecodeMode int

const (
	// JSONUnmarshal reads all the body with io.ReadAll, then calls
	// json.Unmarshal.
	JSONUnmarshal JSONDecodeMode = iota
	// JSONDecoder decodes the body with json.NewDecoder.
	JSONDecoder
)

func (mode JSONDecodeMode) String() string {
	if mode == JSONDecoder {
		return "decoder"
	}
	return "unmarshal"
}

// LargeJSONDocument has a large field before the field that goes to the
// query.
type LargeJSONDocument struct {
	Padding string `json:"padding"`
	Table   string `json:"table"`
}

// BuildLargeJSONQuery decodes body with mode, then writes the table field
// into a bytes.Buffer after a literal prefix.
func BuildLargeJSONQuery(body io.Reader, mode JSONDecodeMode) (string, error) {
	var document LargeJSONDocument
	switch mode {
	case JSONDecoder:
		if err := json.NewDecoder(body).Decode(&document); err != nil {
			return "", err
		}
	default:
		data, err := io.ReadAll(body)
		if err != nil {
			return "", err
		}
		if err := json.Unmarshal(data, &document); err != nil {
			return "", err
		}
	}
	var writer bytes.Buffer
	writer.WriteString("SELECT id FROM ")
	writer.WriteString(document.Table)
	return writer.String(), nil
}
