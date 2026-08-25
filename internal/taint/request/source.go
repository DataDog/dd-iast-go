// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package request holds request-scoped taint data structures that have no
// dependency on the request owner lifetime, the identity store, instrumentation,
// redaction, or model serialization.
//
// Phase 1 provides the bounded request source table: a fixed-capacity,
// deduplicating table of request sources. Source equality is exact over
// (origin, name, full unredacted value). The table keeps the full strings;
// truncation and redaction are later concerns, applied only when materializing a
// report model.
package request

import (
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
)

// SourceID identifies a source within a single request's source [Table].
//
// SourceID is request-local: it is valid only for the [Table] that issued it and
// remains stable until that table is reset. ID 0 is a valid identifier; the
// [AddResult].Status field distinguishes a returned ID from a capacity failure
// or rejected input.
//
// SourceID is shared with range provenance so no conversion seam can associate
// a range with the wrong request source.
type SourceID = ranges.SourceID

// Source is the full unredacted record of a single request source. Equality is
// exact over (Origin, Name, Value).
//
// Live analysis entries contain immutable store-managed strings whose retained
// allocations are charged to the same root as the tainted source value. The
// table-level Add helper retains caller strings directly and is limited to
// isolated table use and tests. Truncation and redaction are applied later,
// only when materializing a report model.
type Source struct {
	Origin constants.Origin
	Name   string
	Value  string
}
