// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

import (
	"encoding/json"
	"fmt"
)

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
)

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
	switch s {
	case "http.request.parameter":
		*o = OriginHttpRequestParameter
	case "http.request.parameter.name":
		*o = OriginHttpRequestParameterName
	case "http.request.header":
		*o = OriginHttpRequestHeader
	case "http.request.header.name":
		*o = OriginHttpRequestHeaderName
	case "http.request.path":
		*o = OriginHttpRequestPath
	case "http.request.body":
		*o = OriginHttpRequestBody
	case "http.request.query":
		*o = OriginHttpRequestQuery
	case "http.request.path.parameter":
		*o = OriginHttpRequestPathParameter
	case "http.request.matrix.parameter":
		*o = OriginHttpRequestMatrixParameter
	case "http.request.cookie.name":
		*o = OriginHttpRequestCookieName
	case "http.request.cookie.value":
		*o = OriginHttpRequestCookieValue
	case "http.request.uri":
		*o = OriginHttpRequestUri
	case "grpc.request.body":
		*o = OriginGrpcRequestBody
	case "http.request.multipart.parameter":
		*o = OriginHttpRequestMultipartParameter
	case "kafka.message.key":
		*o = OriginKafkaMessageKey
	case "kafka.message.value":
		*o = OriginKafkaMessageValue
	case "graphql.resolver.argument":
		*o = OriginGraphqlResolverArgument
	case "sql.row.value":
		*o = OriginSqlRowValue
	default:
		return fmt.Errorf("invalid origin: %s", s)
	}
	return nil
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
		panic(fmt.Errorf("invalid origin: %d", o))
	}
}
