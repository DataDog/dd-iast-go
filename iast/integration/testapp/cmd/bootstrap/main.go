// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Command bootstrap verifies executable-time sink callback registration.
package main

// Keep main empty and do not import the integrations here. CI and
// TestBootstrapProductionPackageEndingInTest check that Orchestrion alone
// links the callback registrations into this executable.
func main() {}
