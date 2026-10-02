// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command bootstrap verifies that the runtime hooks and their callbacks link
// into an executable that imports nothing from dd-iast-go.
package main

// Keep main empty. CI checks that Orchestrion alone links the woven runtime
// wrappers, the bridge and the propagation callbacks into this executable.
func main() {}
