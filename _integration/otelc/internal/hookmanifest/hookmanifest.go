// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package hookmanifest reads the expected-hook manifest: the checked-in list of
// the hooks that a woven build must have.
//
// The manifest is a text file. Each line is empty, a comment (it starts with
// "#"), or an entry of 3 fields separated by white space:
//
//	<go-minor> <goos>/<goarch> <hook>
//
// <go-minor> is a Go minor version without the "go" prefix (for example
// "1.26"), "tip" for a development version of the toolchain, or "*" for all the
// versions. A development version has only the version "tip": an entry for the
// minor version that is in development must be repeated with "tip". The same rule applies to <goos> and
// <goarch>. <hook> is the name of a hook. A line that does not follow this
// format is an error, so a typo cannot silently remove a hook.
package hookmanifest

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Entry is one line of the manifest.
type Entry struct {
	// GoMinor is a Go minor version (for example "1.26") or "*".
	GoMinor string
	// GOOS is an operating system name or "*".
	GOOS string
	// GOARCH is an architecture name or "*".
	GOARCH string
	// Hook is the name of the hook.
	Hook string
}

// Manifest is a list of entries.
type Manifest []Entry

var (
	minorPattern = regexp.MustCompile(`^(\*|[0-9]+\.[0-9]+|tip)$`)
	namePattern  = regexp.MustCompile(`^(\*|[a-z0-9]+)$`)
	hookPattern  = regexp.MustCompile(`^[A-Za-z0-9_.:/()-]+$`)
)

// Parse reads a manifest. It returns an error that names the line number when
// a line has a wrong format, or when 2 entries are the same.
func Parse(r io.Reader) (Manifest, error) {
	var (
		m    Manifest
		seen = make(map[Entry]int)
	)
	scanner := bufio.NewScanner(r)
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("line %d: want 3 fields, got %d", n, len(fields))
		}
		goos, goarch, ok := strings.Cut(fields[1], "/")
		if !ok {
			return nil, fmt.Errorf("line %d: platform %q is not <goos>/<goarch>", n, fields[1])
		}
		entry := Entry{GoMinor: fields[0], GOOS: goos, GOARCH: goarch, Hook: fields[2]}
		switch {
		case !minorPattern.MatchString(entry.GoMinor):
			return nil, fmt.Errorf("line %d: Go version %q is not a minor version", n, entry.GoMinor)
		case !namePattern.MatchString(entry.GOOS), !namePattern.MatchString(entry.GOARCH):
			return nil, fmt.Errorf("line %d: platform %q is not valid", n, fields[1])
		case !hookPattern.MatchString(entry.Hook):
			return nil, fmt.Errorf("line %d: hook name %q is not valid", n, entry.Hook)
		}
		if first, dup := seen[entry]; dup {
			return nil, fmt.Errorf("line %d: same entry as line %d", n, first)
		}
		seen[entry] = n
		m = append(m, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return m, nil
}

// Expected returns the hooks (without duplicates, in the order of the file)
// that a build for the given Go minor version and platform must have.
func (m Manifest) Expected(goMinor, goos, goarch string) []string {
	var (
		hooks []string
		seen  = make(map[string]struct{})
	)
	for _, e := range m {
		if !matches(e.GoMinor, goMinor) || !matches(e.GOOS, goos) || !matches(e.GOARCH, goarch) {
			continue
		}
		if _, dup := seen[e.Hook]; dup {
			continue
		}
		seen[e.Hook] = struct{}{}
		hooks = append(hooks, e.Hook)
	}
	return hooks
}

func matches(pattern, value string) bool {
	return pattern == "*" || pattern == value
}

// GoMinor returns the minor version of a [runtime.Version] value: "1.26" for
// "go1.26.3" or "go1.26rc1". A development version of the toolchain ("devel
// go1.28-abcdef ...", or "go1.28-devel_abcdef ...") gives "tip".
func GoMinor(version string) string {
	if strings.HasPrefix(version, "devel") || strings.Contains(version, "-devel") {
		return "tip"
	}
	version = strings.TrimPrefix(version, "go")
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return version
	}
	minor := parts[1]
	if i := strings.IndexFunc(minor, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minor = minor[:i]
	}
	return parts[0] + "." + minor
}
