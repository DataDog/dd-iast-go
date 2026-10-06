// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package request holds the request owners of the taint analysis: sampling,
// the bounded permits, the per-request sources, derived values and body data,
// and the attribution of tainted bytes to the sources of a request.
//
// The taint itself is in the heap taint bits (package
// internal/taint/heapbits): a bit for each byte. The bits tell only "this
// byte is tainted". The owner data of this package tell which source of
// which request the bytes come from (see [Analysis.AttributeString]).
//
// All the data that an owner keeps are owner copies, charged to a fixed
// budget for each owner ([OwnerBudget]). An owner never keeps a reference to
// memory of the application; it keeps only uintptr locators, which it uses
// only to find a candidate, and then it checks the bytes against its copy.
package request

import "github.com/DataDog/dd-iast-go/internal/model/constants"

// SourceID identifies a source within a single request's source [Table].
//
// SourceID is request-local: it is valid only for the [Table] that issued it and
// remains stable until that table is reset. ID 0 is a valid identifier; the
// [AddResult].Status field distinguishes a returned ID from a capacity failure
// or rejected input.
type SourceID uint16

// BodySourceID is the source of the request body of an owner. It is not in
// the source [Table]: its value is the owner copy of the first body bytes
// (see [MaxBodyCopy]).
const BodySourceID SourceID = MaxSources

// SourceKind records the form of the value of the source that the
// application gave.
type SourceKind uint8

const (
	// SourceString: the application value is a string.
	SourceString SourceKind = iota
	// SourceBytes: the application value is a mutable byte slice. The source
	// value is a copy, so it does not change when the application changes
	// the slice.
	SourceBytes
	// SourceBody: the source is the request body (see [BodySourceID]).
	SourceBody
)

// Source is the full unredacted record of a single request source. Equality is
// exact over (Origin, Name, Value). Kind is not part of source equality.
//
// In a live analysis, Name and Value are owner copies: immutable strings
// that no application code can change. Truncation and redaction are applied
// later, only when materializing a report model.
type Source struct {
	Origin constants.Origin
	Name   string
	Value  string
	Kind   SourceKind
}
