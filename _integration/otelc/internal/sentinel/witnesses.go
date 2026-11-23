// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package sentinel

// witnesses maps the name of each hook of the manifest to a function that
// uses the hook and returns an error when the hook does not work.
var witnesses = map[string]func() error{}
