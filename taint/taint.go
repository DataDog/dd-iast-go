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
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
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

// Marks is an opaque set of vulnerability-specific secure marks.
type Marks struct {
	bits uint64
}

// Has reports whether the range is marked secure for vulnerability.
func (m Marks) Has(vulnerability VulnerabilityType) bool {
	return ranges.HasMark(m.bits, vulnerability)
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

// TaintString returns a managed replacement tainted across its complete byte
// length. It returns value unchanged when analysis is inactive, the value or
// source name exceeds 64 KiB, the value is shorter than two bytes, storage is
// full, or bounded synchronization is contended. Derived substrings need a
// propagation operation before identity lookup can recognize them.
func TaintString[T ~string](ctx context.Context, source Source, value T) T {
	scope := request.FromContext(ctx)
	analysis, ok := scope.Analysis()
	if !ok {
		return value
	}
	managed, ok := analysis.TaintString(source.Origin, source.Name, string(value))
	if !ok {
		return value
	}
	return T(managed)
}

// TaintBytes returns a managed mutable replacement with the same length and
// capacity. Source metadata is copied separately and cannot change when the
// returned bytes are mutated. It returns value unchanged under the same drop
// conditions as TaintString and when the slice capacity exceeds 64 KiB, because
// capacity is the retained and charged span. Reslicing or appending needs a
// propagation or mutation operation before the changed window can be
// recognized.
func TaintBytes[T ~[]byte](ctx context.Context, source Source, value T) T {
	scope := request.FromContext(ctx)
	analysis, ok := scope.Analysis()
	if !ok {
		return value
	}
	managed, ok := analysis.TaintBytes(source.Origin, source.Name, []byte(value))
	if !ok {
		return value
	}
	return T(managed)
}

// IsTaintedString reports whether value has at least one complete live source.
// Contention and owner-finish races safely return false.
func IsTaintedString[T ~string](value T) bool {
	return request.IsTaintedString(string(value))
}

// IsTaintedBytes reports whether value has at least one complete live source.
// Contention and owner-finish races safely return false.
func IsTaintedBytes[T ~[]byte](value T) bool {
	return request.IsTaintedBytes([]byte(value))
}

// VisitString synchronously visits complete live ranges. The callback returns
// true to continue or false to stop. VisitString returns true if it delivered
// at least one range, including when the callback stopped early.
func VisitString[T ~string](value T, visit func(Range) bool) bool {
	if visit == nil {
		return false
	}
	return request.VisitString(string(value), func(resolved request.ResolvedRange) bool {
		return visit(publicRange(resolved))
	})
}

// VisitBytes synchronously visits complete live ranges. The callback returns
// true to continue or false to stop. VisitBytes returns true if it delivered at
// least one range, including when the callback stopped early.
func VisitBytes[T ~[]byte](value T, visit func(Range) bool) bool {
	if visit == nil {
		return false
	}
	return request.VisitBytes([]byte(value), func(resolved request.ResolvedRange) bool {
		return visit(publicRange(resolved))
	})
}

func publicRange(resolved request.ResolvedRange) Range {
	return Range{
		Start:  resolved.Start,
		Length: resolved.Length,
		Source: SourceValue{
			Source: Source{Origin: resolved.Source.Origin, Name: resolved.Source.Name},
			Value:  resolved.Source.Value,
		},
		Marks: Marks{bits: resolved.Marks},
	}
}
