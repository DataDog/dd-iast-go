// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build tools

// This is the tool file of an application that imports the root package of
// dd-iast-go AND a sub-package of it. No rule file must load twice.

package setup

import (
	_ "github.com/DataDog/dd-iast-go"                  // All detections
	_ "github.com/DataDog/dd-iast-go/iast/crypto/hash" // Also a sub-package
)
