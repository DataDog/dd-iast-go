// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package model

import "github.com/tinylib/msgp/msgp"

// encodeMsgpString encodes s as a MessagePack string, for use in negative
// test cases that need syntactically valid-but-semantically-invalid payloads.
func encodeMsgpString(s string) []byte {
	return msgp.AppendString(nil, s)
}
