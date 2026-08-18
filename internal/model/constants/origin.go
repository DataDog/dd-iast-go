// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package constants

import (
	"encoding/json"
	"fmt"
)

//go:generate go tool msgp -io=false -tests=false
//msgp:shim Origin as:string using:(Origin).String/parseOrigin witherr:true

type Origin uint8

const (
	_ Origin = iota
	OriginHttpRequestParameter
	OriginHttpRequestParameterName
	OriginHttpRequestHeader
	OriginHttpRequestHeaderName
	OriginHttpRequestPath
	OriginHttpRequestBody
	OriginHttpRequestQuery
	OriginHttpRequestPathParameter
	OriginHttpRequestMatrixParameter
	OriginHttpRequestCookieName
	OriginHttpRequestCookieValue
	OriginHttpRequestUri
	OriginGrpcRequestBody
	OriginHttpRequestMultipartParameter
	OriginKafkaMessageKey
	OriginKafkaMessageValue
	OriginGraphqlResolverArgument
	OriginSqlRowValue

	// originCount is the total number of [Origin] values that exist. This is used
	// for testing.
	originCount uint = iota - 1
)

// AllOrigins returns the list of all existing [Origin] values by their constant
// name without the "Origin" prefix. This is used for testing.
func AllOrigins() map[string]Origin {
	origins := make(map[string]Origin, originCount)
	for i := range originCount {
		o := Origin(i + 1)
		origins[o.name()] = o
	}
	return origins
}

// name returns the name of the [Origin] constant without the "Origin" prefix.
// This is used for testing.
func (o Origin) name() string {
	switch o {
	case OriginHttpRequestParameter:
		return "HttpRequestParameter"
	case OriginHttpRequestParameterName:
		return "HttpRequestParameterName"
	case OriginHttpRequestHeader:
		return "HttpRequestHeader"
	case OriginHttpRequestHeaderName:
		return "HttpRequestHeaderName"
	case OriginHttpRequestPath:
		return "HttpRequestPath"
	case OriginHttpRequestBody:
		return "HttpRequestBody"
	case OriginHttpRequestQuery:
		return "HttpRequestQuery"
	case OriginHttpRequestPathParameter:
		return "HttpRequestPathParameter"
	case OriginHttpRequestMatrixParameter:
		return "HttpRequestMatrixParameter"
	case OriginHttpRequestCookieName:
		return "HttpRequestCookieName"
	case OriginHttpRequestCookieValue:
		return "HttpRequestCookieValue"
	case OriginHttpRequestUri:
		return "HttpRequestUri"
	case OriginGrpcRequestBody:
		return "GrpcRequestBody"
	case OriginHttpRequestMultipartParameter:
		return "HttpRequestMultipartParameter"
	case OriginKafkaMessageKey:
		return "KafkaMessageKey"
	case OriginKafkaMessageValue:
		return "KafkaMessageValue"
	case OriginGraphqlResolverArgument:
		return "GraphqlResolverArgument"
	case OriginSqlRowValue:
		return "SqlRowValue"
	default:
		panic(fmt.Errorf("invalid Origin value: 0x%02X", o))
	}
}

func (o Origin) String() string {
	switch o {
	case OriginHttpRequestParameter:
		return "http.request.parameter"
	case OriginHttpRequestParameterName:
		return "http.request.parameter.name"
	case OriginHttpRequestHeader:
		return "http.request.header"
	case OriginHttpRequestHeaderName:
		return "http.request.header.name"
	case OriginHttpRequestPath:
		return "http.request.path"
	case OriginHttpRequestBody:
		return "http.request.body"
	case OriginHttpRequestQuery:
		return "http.request.query"
	case OriginHttpRequestPathParameter:
		return "http.request.path.parameter"
	case OriginHttpRequestMatrixParameter:
		return "http.request.matrix.parameter"
	case OriginHttpRequestCookieName:
		return "http.request.cookie.name"
	case OriginHttpRequestCookieValue:
		return "http.request.cookie.value"
	case OriginHttpRequestUri:
		return "http.request.uri"
	case OriginGrpcRequestBody:
		return "grpc.request.body"
	case OriginHttpRequestMultipartParameter:
		return "http.request.multipart.parameter"
	case OriginKafkaMessageKey:
		return "kafka.message.key"
	case OriginKafkaMessageValue:
		return "kafka.message.value"
	case OriginGraphqlResolverArgument:
		return "graphql.resolver.argument"
	case OriginSqlRowValue:
		return "sql.row.value"
	default:
		return fmt.Sprintf("Origin(%d)", o)
	}
}

func parseOrigin(s string) (Origin, error) {
	switch s {
	case "http.request.parameter":
		return OriginHttpRequestParameter, nil
	case "http.request.parameter.name":
		return OriginHttpRequestParameterName, nil
	case "http.request.header":
		return OriginHttpRequestHeader, nil
	case "http.request.header.name":
		return OriginHttpRequestHeaderName, nil
	case "http.request.path":
		return OriginHttpRequestPath, nil
	case "http.request.body":
		return OriginHttpRequestBody, nil
	case "http.request.query":
		return OriginHttpRequestQuery, nil
	case "http.request.path.parameter":
		return OriginHttpRequestPathParameter, nil
	case "http.request.matrix.parameter":
		return OriginHttpRequestMatrixParameter, nil
	case "http.request.cookie.name":
		return OriginHttpRequestCookieName, nil
	case "http.request.cookie.value":
		return OriginHttpRequestCookieValue, nil
	case "http.request.uri":
		return OriginHttpRequestUri, nil
	case "grpc.request.body":
		return OriginGrpcRequestBody, nil
	case "http.request.multipart.parameter":
		return OriginHttpRequestMultipartParameter, nil
	case "kafka.message.key":
		return OriginKafkaMessageKey, nil
	case "kafka.message.value":
		return OriginKafkaMessageValue, nil
	case "graphql.resolver.argument":
		return OriginGraphqlResolverArgument, nil
	case "sql.row.value":
		return OriginSqlRowValue, nil
	default:
		return 0, fmt.Errorf("invalid origin: %s", s)
	}
}

var (
	_ json.Marshaler   = Origin(0)
	_ json.Unmarshaler = (*Origin)(nil)
)

func (o Origin) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.String())
}

func (o *Origin) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	res, err := parseOrigin(s)
	*o = res
	return err
}
