// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

import (
	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

//go:generate go tool msgp -io=false -tests=false

type Source struct {
	Origin    constants.Origin `json:"origin" msg:"origin"`
	Name      string           `json:"name,omitempty" msg:"name,omitempty"`
	Value     string           `json:"value,omitempty" msg:"value,omitempty"`
	Pattern   string           `json:"pattern,omitempty" msg:"pattern,omitempty"`
	Redacted  bool             `json:"redacted,omitzero" msg:"redacted,omitempty"`
	Truncated TruncatedSide    `json:"truncated,omitzero" msg:"truncated,omitzero"`
}

func NewSourceString(origin constants.Origin, name string, value string) Source {
	value, truncated := truncateStringIfNeeded(value)
	return Source{
		Origin:    origin,
		Name:      name,
		Value:     value,
		Truncated: truncated,
	}
}

func NewSourceRedactedString(origin constants.Origin, name string, pattern string) Source {
	pattern, truncated := truncateStringIfNeeded(pattern)
	return Source{
		Origin:    origin,
		Name:      name,
		Pattern:   pattern,
		Redacted:  true,
		Truncated: truncated,
	}
}
