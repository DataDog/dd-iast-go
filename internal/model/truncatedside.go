// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DataDog/dd-iast-go/internal/config"
)

//go:generate go tool msgp -io=false -tests=false
//msgp:shim TruncatedSide as:string using:(TruncatedSide).String/parseTruncatedSide witherr:true

type TruncatedSide uint8

const (
	TruncatedSideNone TruncatedSide = iota
	TruncatedSideRight
)

// truncateStringIfNeeded truncates a string if it is longer than [config.TruncationMaxValue], and
// returns a [strings.Clone] in such cases, in order to avoid retaining the original long string. If
// the string contains at most [config.TruncationMaxValue] characters, it is returned as-is.
func truncateStringIfNeeded(s string) (string, TruncatedSide) {
	if uint64(len(s)) <= config.TruncationMaxValue {
		return s, TruncatedSideNone
	}

	var characters uint64
	for index := range s {
		if characters == config.TruncationMaxValue {
			return strings.Clone(s[:index]), TruncatedSideRight
		}
		characters++
	}
	return s, TruncatedSideNone
}

func (t TruncatedSide) String() string {
	switch t {
	case TruncatedSideNone:
		return ""
	case TruncatedSideRight:
		return "right"
	default:
		return "<invalid>"
	}
}

func parseTruncatedSide(s string) (TruncatedSide, error) {
	switch s {
	case "":
		return TruncatedSideNone, nil
	case "right":
		return TruncatedSideRight, nil
	default:
		return 0, fmt.Errorf("unknown/invalid truncated side: %s", s)
	}
}

func (t TruncatedSide) IsZero() bool {
	return t == TruncatedSideNone
}

func (t TruncatedSide) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *TruncatedSide) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	res, err := parseTruncatedSide(s)
	if err != nil {
		return err
	}
	*t = res
	return nil
}
