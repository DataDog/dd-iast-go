// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build ignore

// This file is not part of the "hash" package. The otelc rules in otelc.yml
// ("md4_declarations") copy it into the package "golang.org/x/crypto/md4" at
// build time. The "//go:build ignore" constraint keeps it out of this package.
//
// The file MUST import only the standard library and "unsafe" (never a package
// of this module): it is compiled inside "golang.org/x/crypto/md4".

package md4

import (
	"context"
	"crypto"
	_ "unsafe" // For go:linkname
)

//go:linkname __dd__iast_ReportWeakHash__ github.com/DataDog/dd-iast-go/iast/crypto/hash.ReportWeakHash
func __dd__iast_ReportWeakHash__(context.Context, crypto.Hash)

//go:linkname __dd__iast_RegisterWeakHashSinks__ github.com/DataDog/dd-iast-go/iast/crypto/hash.RegisterInstrumentedSinks
func __dd__iast_RegisterWeakHashSinks__(count uint)

// The init function below only calls a function that adds to a statically
// allocated counter (zero at load time). It MUST NOT write to a value that needs
// run-time initialization (map, slice, pointer): this init function can run
// before the init functions of every package of this module.
func init() {
	// Keep this number equal to the count of "inject_code" rules that target
	// "golang.org/x/crypto/md4" in otelc.yml (md4.New).
	__dd__iast_RegisterWeakHashSinks__(1)
}
