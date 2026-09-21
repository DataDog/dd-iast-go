// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command bootstrap verifies executable-time SQL sink callback registration.
package main

// Keep main empty and do not import the SQL integration here. CI checks that
// Orchestrion alone links its callback registration into this executable.
// This is a link-time fixture, not a command-injection payload.
func main() {}
