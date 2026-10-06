// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package taint provides bounded, request-scoped taint source and inspection
// operations for IAST integrations.
package taint

import (
	"context"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
)

// Origin identifies the kind of input source.
type Origin = constants.Origin

const (
	OriginHttpRequestParameter          = constants.OriginHttpRequestParameter
	OriginHttpRequestParameterName      = constants.OriginHttpRequestParameterName
	OriginHttpRequestHeader             = constants.OriginHttpRequestHeader
	OriginHttpRequestHeaderName         = constants.OriginHttpRequestHeaderName
	OriginHttpRequestPath               = constants.OriginHttpRequestPath
	OriginHttpRequestBody               = constants.OriginHttpRequestBody
	OriginHttpRequestQuery              = constants.OriginHttpRequestQuery
	OriginHttpRequestPathParameter      = constants.OriginHttpRequestPathParameter
	OriginHttpRequestMatrixParameter    = constants.OriginHttpRequestMatrixParameter
	OriginHttpRequestCookieName         = constants.OriginHttpRequestCookieName
	OriginHttpRequestCookieValue        = constants.OriginHttpRequestCookieValue
	OriginHttpRequestUri                = constants.OriginHttpRequestUri
	OriginGrpcRequestBody               = constants.OriginGrpcRequestBody
	OriginHttpRequestMultipartParameter = constants.OriginHttpRequestMultipartParameter
	OriginKafkaMessageKey               = constants.OriginKafkaMessageKey
	OriginKafkaMessageValue             = constants.OriginKafkaMessageValue
	OriginGraphqlResolverArgument       = constants.OriginGraphqlResolverArgument
	OriginSqlRowValue                   = constants.OriginSqlRowValue
)

// VulnerabilityType identifies a vulnerability class and its secure mark.
type VulnerabilityType = constants.VulnerabilityType

const (
	VulnerabilityTypeAdminConsoleActive        = constants.VulnerabilityTypeAdminConsoleActive
	VulnerabilityTypeCodeInjection             = constants.VulnerabilityTypeCodeInjection
	VulnerabilityTypeCommandInjection          = constants.VulnerabilityTypeCommandInjection
	VulnerabilityTypeDefaultHtmlEscapeInvalid  = constants.VulnerabilityTypeDefaultHtmlEscapeInvalid
	VulnerabilityTypeDirectoryListingLeak      = constants.VulnerabilityTypeDirectoryListingLeak
	VulnerabilityTypeEmailHtmlInjection        = constants.VulnerabilityTypeEmailHtmlInjection
	VulnerabilityTypeHardcodedKey              = constants.VulnerabilityTypeHardcodedKey
	VulnerabilityTypeHardcodedPassword         = constants.VulnerabilityTypeHardcodedPassword
	VulnerabilityTypeHardcodedSecret           = constants.VulnerabilityTypeHardcodedSecret
	VulnerabilityTypeHeaderInjection           = constants.VulnerabilityTypeHeaderInjection
	VulnerabilityTypeHstsHeaderMissing         = constants.VulnerabilityTypeHstsHeaderMissing
	VulnerabilityTypeInsecureAuthProtocol      = constants.VulnerabilityTypeInsecureAuthProtocol
	VulnerabilityTypeInsecureCookie            = constants.VulnerabilityTypeInsecureCookie
	VulnerabilityTypeInsecureJspLayout         = constants.VulnerabilityTypeInsecureJspLayout
	VulnerabilityTypeLdapInjection             = constants.VulnerabilityTypeLdapInjection
	VulnerabilityTypeNosqlMongodbInjection     = constants.VulnerabilityTypeNosqlMongodbInjection
	VulnerabilityTypeNoHttponlyCookie          = constants.VulnerabilityTypeNoHttponlyCookie
	VulnerabilityTypeNoSamesiteCookie          = constants.VulnerabilityTypeNoSamesiteCookie
	VulnerabilityTypePathTraversal             = constants.VulnerabilityTypePathTraversal
	VulnerabilityTypeReflectionInjection       = constants.VulnerabilityTypeReflectionInjection
	VulnerabilityTypeSessionRewriting          = constants.VulnerabilityTypeSessionRewriting
	VulnerabilityTypeSessionTimeout            = constants.VulnerabilityTypeSessionTimeout
	VulnerabilityTypeSqlInjection              = constants.VulnerabilityTypeSqlInjection
	VulnerabilityTypeSsrf                      = constants.VulnerabilityTypeSsrf
	VulnerabilityTypeStacktraceLeak            = constants.VulnerabilityTypeStacktraceLeak
	VulnerabilityTypeTemplateInjection         = constants.VulnerabilityTypeTemplateInjection
	VulnerabilityTypeTrustBoundaryViolation    = constants.VulnerabilityTypeTrustBoundaryViolation
	VulnerabilityTypeUntrustedDeserialization  = constants.VulnerabilityTypeUntrustedDeserialization
	VulnerabilityTypeUnvalidatedRedirect       = constants.VulnerabilityTypeUnvalidatedRedirect
	VulnerabilityTypeVerbTampering             = constants.VulnerabilityTypeVerbTampering
	VulnerabilityTypeWeakCipher                = constants.VulnerabilityTypeWeakCipher
	VulnerabilityTypeWeakHash                  = constants.VulnerabilityTypeWeakHash
	VulnerabilityTypeWeakRandomness            = constants.VulnerabilityTypeWeakRandomness
	VulnerabilityTypeXcontenttypeHeaderMissing = constants.VulnerabilityTypeXcontenttypeHeaderMissing
	VulnerabilityTypeXpathInjection            = constants.VulnerabilityTypeXpathInjection
	VulnerabilityTypeXss                       = constants.VulnerabilityTypeXss
)

// Source describes a value's source. Name is empty when the source kind has no
// name, such as a request body.
type Source struct {
	Origin Origin
	Name   string
}

// SourceValue is a copied source record. Value can contain arbitrary bytes.
type SourceValue struct {
	Source
	Value string
}

// Marks is an opaque set of vulnerability-specific secure marks. No code sets
// marks yet: the set is always empty.
type Marks struct {
	_ struct{}
}

// Has reports whether the range is marked secure for vulnerability. It is
// always false: no code sets marks yet.
func (m Marks) Has(vulnerability VulnerabilityType) bool {
	return false
}

// Range describes one tainted byte interval and its complete source metadata.
// Source strings are borrowed for the synchronous Visit call and should not be
// retained by instrumentation after the callback returns.
type Range struct {
	Start  uint32
	Length uint32
	Source SourceValue
	Marks  Marks
}

// TaintString marks value as tainted by source for the request of ctx, and
// returns it. Every substring of the returned value is also tainted, and
// so are the copies that the propagation makes.
//
// The taint is set in place when possible. When value is in memory that
// cannot be tainted (read-only data such as a string literal, or stack
// memory), TaintString returns a tainted heap clone. It returns value
// unchanged when analysis is inactive, the source has no valid origin, the
// value is shorter than two bytes or longer than 64 KiB, the source name is
// longer than 256 bytes, the request storage is full, or bounded
// synchronization is contended.
func TaintString[T ~string](ctx context.Context, source Source, value T) T {
	analysis, ok := request.FromContext(ctx).Analysis()
	if !ok {
		return value
	}
	tainted, ok := analysis.TaintString(source.Origin, source.Name, string(value))
	if !ok {
		return value
	}
	return T(tainted)
}

// TaintBytes marks value as tainted by source for the request of ctx, and
// returns it. The source value is a copy, which does not change when value
// is changed. The taint is set in place when possible; else TaintBytes
// returns a tainted heap clone with the same length and capacity. It returns
// value unchanged under the same drop conditions as TaintString, and also
// when a clone is necessary but cap(value) is more than 64 KiB (the clone
// must keep the capacity, and a larger clone is not bounded).
//
// The taint describes the memory: after a write into the returned value,
// the changed bytes stay tainted, but a report attributes them to the source
// only when they are still equal to the source value.
func TaintBytes[T ~[]byte](ctx context.Context, source Source, value T) T {
	analysis, ok := request.FromContext(ctx).Analysis()
	if !ok {
		return value
	}
	tainted, ok := analysis.TaintBytes(source.Origin, source.Name, []byte(value))
	if !ok {
		return value
	}
	return T(tainted)
}

// IsTaintedString reports whether at least one byte of value comes from a
// source of an active request. It is false after the request finished.
// Contention safely returns false.
func IsTaintedString[T ~string](value T) bool {
	return request.IsTaintedString(string(value))
}

// IsTaintedBytes reports whether at least one byte of value comes from a
// source of an active request. It is false after the request finished.
// Contention safely returns false.
func IsTaintedBytes[T ~[]byte](value T) bool {
	return request.IsTaintedBytes([]byte(value))
}

// VisitString synchronously visits the ranges of value that come from a
// source of the request of ctx. It never visits bytes of a different
// request, also when value is shared by more than one request. The callback
// returns true to continue or false to stop. VisitString returns true if it
// delivered at least one range, including when the callback stopped early. It
// returns false when ctx has no active request analysis.
func VisitString[T ~string](ctx context.Context, value T, visit func(Range) bool) bool {
	if visit == nil {
		return false
	}
	owner, ok := contextOwner(ctx)
	if !ok {
		return false
	}
	return request.VisitStringOwner(string(value), owner, func(resolved request.ResolvedRange) bool {
		return visit(publicRange(resolved))
	})
}

// VisitBytes synchronously visits the ranges of value that come from a
// source of the request of ctx. See VisitString.
func VisitBytes[T ~[]byte](ctx context.Context, value T, visit func(Range) bool) bool {
	if visit == nil {
		return false
	}
	owner, ok := contextOwner(ctx)
	if !ok {
		return false
	}
	return request.VisitBytesOwner([]byte(value), owner, func(resolved request.ResolvedRange) bool {
		return visit(publicRange(resolved))
	})
}

func contextOwner(ctx context.Context) (request.Owner, bool) {
	analysis, ok := request.FromContext(ctx).Analysis()
	if !ok {
		return request.Owner{}, false
	}
	return analysis.Owner()
}

func publicRange(resolved request.ResolvedRange) Range {
	return Range{
		Start:  resolved.Start,
		Length: resolved.Length,
		Source: SourceValue{
			Source: Source{Origin: resolved.Source.Origin, Name: resolved.Source.Name},
			Value:  resolved.Source.Value,
		},
	}
}
