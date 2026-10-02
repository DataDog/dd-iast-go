// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package telemetry contains the metric value storage for conflated telemetry
// metrics specified for IAST. These are submitted to the instrumentation
// telemetry backend by the
// [github.com/DataDog/dd-iast-go/spans] package in order to keep this package
// dependency-free so it's easier to inject just about anywhere without having
// to worry about creating dependency cycles.
package telemetry

import (
	"sync/atomic"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
)

// Build-time metrics. These are modified only by `init` functions inserted at
// build time by the instrumentation; which is why they don't need to be atomic
// or synchronized.
var (
	// InstrumentedSource is the number of sources instrumented during build.
	InstrumentedSource = make(map[constants.Origin]uint, constants.OriginCount)
	// InstrumentedPropagation is the number of propagation points instrumented during the build.
	InstrumentedPropagation = uint(0)
	// InstrumentedSink is the number of sinks instrumented during the build.
	InstrumentedSink = make(map[constants.VulnerabilityType]uint, constants.VulnerabilityTypeCount)
)

// Run-time metrics. These are modified by the running application and have to
// be atomic or synchronized.
var (
	// ExecutedTainted is the number of tainted operations executed since the last heartbeat.
	ExecutedTainted atomic.Uint64
	// ExecutedSource is the number of instrumented sources that have actually been executed since the last heartbeat.
	ExecutedSource executedSource
	// ExecutedPropagation is the number of propagations that have actually been executed since the last heartbeat.
	ExecutedPropagation atomic.Uint64
	// CoarsenedPropagation is the number of propagations that used coarse ranges.
	CoarsenedPropagation atomic.Uint64
	// DroppedPropagation is the number of bounded propagation contributions dropped.
	DroppedPropagation atomic.Uint64
	// ExecutedSink is the number of instrumented sinks that have actually been executed since the last heartbeat.
	ExecutedSink executedSink
)

type executedSource struct {
	HttpRequestParameter          atomic.Uint64
	HttpRequestParameterName      atomic.Uint64
	HttpRequestHeader             atomic.Uint64
	HttpRequestHeaderName         atomic.Uint64
	HttpRequestPath               atomic.Uint64
	HttpRequestBody               atomic.Uint64
	HttpRequestQuery              atomic.Uint64
	HttpRequestPathParameter      atomic.Uint64
	HttpRequestMatrixParameter    atomic.Uint64
	HttpRequestCookieName         atomic.Uint64
	HttpRequestCookieValue        atomic.Uint64
	HttpRequestUri                atomic.Uint64
	GrpcRequestBody               atomic.Uint64
	HttpRequestMultipartParameter atomic.Uint64
	KafkaMessageKey               atomic.Uint64
	KafkaMessageValue             atomic.Uint64
	GraphqlResolverArgument       atomic.Uint64
	SqlRowValue                   atomic.Uint64
}

func (e *executedSource) Each(yield func(org constants.Origin, count *atomic.Uint64) bool) {
	if !yield(constants.OriginHttpRequestParameter, &e.HttpRequestParameter) {
		return
	}
	if !yield(constants.OriginHttpRequestParameterName, &e.HttpRequestParameterName) {
		return
	}
	if !yield(constants.OriginHttpRequestHeader, &e.HttpRequestHeader) {
		return
	}
	if !yield(constants.OriginHttpRequestHeaderName, &e.HttpRequestHeaderName) {
		return
	}
	if !yield(constants.OriginHttpRequestPath, &e.HttpRequestPath) {
		return
	}
	if !yield(constants.OriginHttpRequestBody, &e.HttpRequestBody) {
		return
	}
	if !yield(constants.OriginHttpRequestQuery, &e.HttpRequestQuery) {
		return
	}
	if !yield(constants.OriginHttpRequestPathParameter, &e.HttpRequestPathParameter) {
		return
	}
	if !yield(constants.OriginHttpRequestMatrixParameter, &e.HttpRequestMatrixParameter) {
		return
	}
	if !yield(constants.OriginHttpRequestCookieName, &e.HttpRequestCookieName) {
		return
	}
	if !yield(constants.OriginHttpRequestCookieValue, &e.HttpRequestCookieValue) {
		return
	}
	if !yield(constants.OriginHttpRequestUri, &e.HttpRequestUri) {
		return
	}
	if !yield(constants.OriginGrpcRequestBody, &e.GrpcRequestBody) {
		return
	}
	if !yield(constants.OriginHttpRequestMultipartParameter, &e.HttpRequestMultipartParameter) {
		return
	}
	if !yield(constants.OriginKafkaMessageKey, &e.KafkaMessageKey) {
		return
	}
	if !yield(constants.OriginKafkaMessageValue, &e.KafkaMessageValue) {
		return
	}
	if !yield(constants.OriginGraphqlResolverArgument, &e.GraphqlResolverArgument) {
		return
	}
	if !yield(constants.OriginSqlRowValue, &e.SqlRowValue) {
		return
	}
}

type executedSink struct {
	AdminConsoleActive        atomic.Uint64
	CodeInjection             atomic.Uint64
	CommandInjection          atomic.Uint64
	DefaultHtmlEscapeInvalid  atomic.Uint64
	DirectoryListingLeak      atomic.Uint64
	EmailHtmlInjection        atomic.Uint64
	HardcodedKey              atomic.Uint64
	HardcodedPassword         atomic.Uint64
	HardcodedSecret           atomic.Uint64
	HeaderInjection           atomic.Uint64
	HstsHeaderMissing         atomic.Uint64
	InsecureAuthProtocol      atomic.Uint64
	InsecureCookie            atomic.Uint64
	InsecureJspLayout         atomic.Uint64
	LdapInjection             atomic.Uint64
	NosqlMongodbInjection     atomic.Uint64
	NoHttponlyCookie          atomic.Uint64
	NoSamesiteCookie          atomic.Uint64
	PathTraversal             atomic.Uint64
	ReflectionInjection       atomic.Uint64
	SessionRewriting          atomic.Uint64
	SessionTimeout            atomic.Uint64
	SqlInjection              atomic.Uint64
	Ssrf                      atomic.Uint64
	StacktraceLeak            atomic.Uint64
	TemplateInjection         atomic.Uint64
	TrustBoundaryViolation    atomic.Uint64
	UntrustedDeserialization  atomic.Uint64
	UnvalidatedRedirect       atomic.Uint64
	VerbTampering             atomic.Uint64
	WeakCipher                atomic.Uint64
	WeakHash                  atomic.Uint64
	WeakRandomness            atomic.Uint64
	XcontenttypeHeaderMissing atomic.Uint64
	XpathInjection            atomic.Uint64
	Xss                       atomic.Uint64
}

func (e *executedSink) Each(yield func(vulnType constants.VulnerabilityType, count *atomic.Uint64) bool) {
	if !yield(constants.VulnerabilityTypeAdminConsoleActive, &e.AdminConsoleActive) {
		return
	}
	if !yield(constants.VulnerabilityTypeCodeInjection, &e.CodeInjection) {
		return
	}
	if !yield(constants.VulnerabilityTypeCommandInjection, &e.CommandInjection) {
		return
	}
	if !yield(constants.VulnerabilityTypeDefaultHtmlEscapeInvalid, &e.DefaultHtmlEscapeInvalid) {
		return
	}
	if !yield(constants.VulnerabilityTypeDirectoryListingLeak, &e.DirectoryListingLeak) {
		return
	}
	if !yield(constants.VulnerabilityTypeEmailHtmlInjection, &e.EmailHtmlInjection) {
		return
	}
	if !yield(constants.VulnerabilityTypeHardcodedKey, &e.HardcodedKey) {
		return
	}
	if !yield(constants.VulnerabilityTypeHardcodedPassword, &e.HardcodedPassword) {
		return
	}
	if !yield(constants.VulnerabilityTypeHardcodedSecret, &e.HardcodedSecret) {
		return
	}
	if !yield(constants.VulnerabilityTypeHeaderInjection, &e.HeaderInjection) {
		return
	}
	if !yield(constants.VulnerabilityTypeHstsHeaderMissing, &e.HstsHeaderMissing) {
		return
	}
	if !yield(constants.VulnerabilityTypeInsecureAuthProtocol, &e.InsecureAuthProtocol) {
		return
	}
	if !yield(constants.VulnerabilityTypeInsecureCookie, &e.InsecureCookie) {
		return
	}
	if !yield(constants.VulnerabilityTypeInsecureJspLayout, &e.InsecureJspLayout) {
		return
	}
	if !yield(constants.VulnerabilityTypeLdapInjection, &e.LdapInjection) {
		return
	}
	if !yield(constants.VulnerabilityTypeNosqlMongodbInjection, &e.NosqlMongodbInjection) {
		return
	}
	if !yield(constants.VulnerabilityTypeNoHttponlyCookie, &e.NoHttponlyCookie) {
		return
	}
	if !yield(constants.VulnerabilityTypeNoSamesiteCookie, &e.NoSamesiteCookie) {
		return
	}
	if !yield(constants.VulnerabilityTypePathTraversal, &e.PathTraversal) {
		return
	}
	if !yield(constants.VulnerabilityTypeReflectionInjection, &e.ReflectionInjection) {
		return
	}
	if !yield(constants.VulnerabilityTypeSessionRewriting, &e.SessionRewriting) {
		return
	}
	if !yield(constants.VulnerabilityTypeSessionTimeout, &e.SessionTimeout) {
		return
	}
	if !yield(constants.VulnerabilityTypeSqlInjection, &e.SqlInjection) {
		return
	}
	if !yield(constants.VulnerabilityTypeSsrf, &e.Ssrf) {
		return
	}
	if !yield(constants.VulnerabilityTypeStacktraceLeak, &e.StacktraceLeak) {
		return
	}
	if !yield(constants.VulnerabilityTypeTemplateInjection, &e.TemplateInjection) {
		return
	}
	if !yield(constants.VulnerabilityTypeTrustBoundaryViolation, &e.TrustBoundaryViolation) {
		return
	}
	if !yield(constants.VulnerabilityTypeUntrustedDeserialization, &e.UntrustedDeserialization) {
		return
	}
	if !yield(constants.VulnerabilityTypeUnvalidatedRedirect, &e.UnvalidatedRedirect) {
		return
	}
	if !yield(constants.VulnerabilityTypeVerbTampering, &e.VerbTampering) {
		return
	}
	if !yield(constants.VulnerabilityTypeWeakCipher, &e.WeakCipher) {
		return
	}
	if !yield(constants.VulnerabilityTypeWeakHash, &e.WeakHash) {
		return
	}
	if !yield(constants.VulnerabilityTypeWeakRandomness, &e.WeakRandomness) {
		return
	}
	if !yield(constants.VulnerabilityTypeXcontenttypeHeaderMissing, &e.XcontenttypeHeaderMissing) {
		return
	}
	if !yield(constants.VulnerabilityTypeXpathInjection, &e.XpathInjection) {
		return
	}
	if !yield(constants.VulnerabilityTypeXss, &e.Xss) {
		return
	}
}
