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
	HTTP_REQUEST_PARAMETER
	HTTP_REQUEST_PARAMETER_NAME
	HTTP_REQUEST_HEADER
	HTTP_REQUEST_HEADER_NAME
	HTTP_REQUEST_PATH
	HTTP_REQUEST_BODY
	HTTP_REQUEST_QUERY
	HTTP_REQUEST_PATH_PARAMETER
	HTTP_REQUEST_MATRIX_PARAMETER
	HTTP_REQUEST_COOKIE_NAME
	HTTP_REQUEST_COOKIE_VALUE
	HTTP_REQUEST_URI
	GRPC_REQUEST_BODY
	HTTP_REQUEST_MULTIPART_PARAMETER
	KAFKA_MESSAGE_KEY
	KAFKA_MESSAGE_VALUE
	GRAPHQL_RESOLVER_ARGUMENT
	SQL_ROW_VALUE
)

var _ json.Marshaler = Origin(0)

func (o Origin) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.String())
}

func (o Origin) String() string {
	switch o {
	case HTTP_REQUEST_PARAMETER:
		return "http.request.parameter"
	case HTTP_REQUEST_PARAMETER_NAME:
		return "http.request.parameter.name"
	case HTTP_REQUEST_HEADER:
		return "http.request.header"
	case HTTP_REQUEST_HEADER_NAME:
		return "http.request.header.name"
	case HTTP_REQUEST_PATH:
		return "http.request.path"
	case HTTP_REQUEST_BODY:
		return "http.request.body"
	case HTTP_REQUEST_QUERY:
		return "http.request.query"
	case HTTP_REQUEST_PATH_PARAMETER:
		return "http.request.path.parameter"
	case HTTP_REQUEST_MATRIX_PARAMETER:
		return "http.request.matrix.parameter"
	case HTTP_REQUEST_COOKIE_NAME:
		return "http.request.cookie.name"
	case HTTP_REQUEST_COOKIE_VALUE:
		return "http.request.cookie.value"
	case HTTP_REQUEST_URI:
		return "http.request.uri"
	case GRPC_REQUEST_BODY:
		return "grpc.request.body"
	case HTTP_REQUEST_MULTIPART_PARAMETER:
		return "http.request.multipart.parameter"
	case KAFKA_MESSAGE_KEY:
		return "kafka.message.key"
	case KAFKA_MESSAGE_VALUE:
		return "kafka.message.value"
	case GRAPHQL_RESOLVER_ARGUMENT:
		return "graphql.resolver.argument"
	case SQL_ROW_VALUE:
		return "sql.row.value"
	default:
		panic(fmt.Errorf("invalid origin: %d", o))
	}
}
