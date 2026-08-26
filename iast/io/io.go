// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package io instruments reader provenance and owned io.ReadAll results.
package io

import _ "github.com/DataDog/dd-iast-go/internal/taint/request" // register callbacks
