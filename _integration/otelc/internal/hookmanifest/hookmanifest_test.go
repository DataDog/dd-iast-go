// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package hookmanifest_test

import (
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/_integration/otelc/internal/hookmanifest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEmpty(t *testing.T) {
	m, err := hookmanifest.Parse(strings.NewReader("# only a comment\n\n   \n"))
	require.NoError(t, err)
	assert.Empty(t, m)
	assert.Empty(t, m.Expected("1.26", "linux", "amd64"))
}

func TestExpected(t *testing.T) {
	m, err := hookmanifest.Parse(strings.NewReader(`
# Comment
* */* everywhere
1.26 linux/amd64 only-126-linux-amd64
1.27 linux/* only-127-linux
* darwin/arm64 only-darwin-arm64
`))
	require.NoError(t, err)

	assert.Equal(t, []string{"everywhere", "only-126-linux-amd64"}, m.Expected("1.26", "linux", "amd64"))
	assert.Equal(t, []string{"everywhere", "only-127-linux"}, m.Expected("1.27", "linux", "arm64"))
	assert.Equal(t, []string{"everywhere", "only-darwin-arm64"}, m.Expected("1.27", "darwin", "arm64"))
	assert.Equal(t, []string{"everywhere"}, m.Expected("tip", "windows", "amd64"))
}

func TestParseErrors(t *testing.T) {
	for name, input := range map[string]string{
		"too few fields":  "1.26 linux/amd64\n",
		"too many fields": "1.26 linux/amd64 a b\n",
		"no slash":        "1.26 linux a\n",
		"bad minor":       "1.26.3 linux/amd64 a\n",
		"bad platform":    "1.26 Linux/amd64 a\n",
		"bad hook":        "1.26 linux/amd64 a;b\n",
		"wildcard hook":   "1.26 linux/amd64 *\n",
		"empty goarch":    "1.26 linux/ a\n",
		"empty goos":      "1.26 /amd64 a\n",
		"extra slash":     "1.26 linux/amd64/x a\n",
		"duplicate":       "1.26 linux/amd64 a\n1.26 linux/amd64 a\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := hookmanifest.Parse(strings.NewReader(input))
			assert.Error(t, err)
		})
	}
}

func TestParseErrorNamesTheLine(t *testing.T) {
	_, err := hookmanifest.Parse(strings.NewReader("# comment\n1.26 linux/amd64 a\n1.26 linux/amd64 a\n"))
	assert.ErrorContains(t, err, "line 3: same entry as line 2")
}

func TestTip(t *testing.T) {
	m, err := hookmanifest.Parse(strings.NewReader("tip */* only-tip\r\n1.28 */* only-128\n"))
	require.NoError(t, err)
	assert.Equal(t, []string{"only-tip"}, m.Expected("tip", "linux", "amd64"))
	assert.Equal(t, []string{"only-128"}, m.Expected("1.28", "linux", "amd64"))
}

func TestGoMinor(t *testing.T) {
	for version, want := range map[string]string{
		"go1.26.3":                    "1.26",
		"go1.27":                      "1.27",
		"go1.28rc1":                   "1.28",
		"devel go1.28-abcdef Mon Jan": "tip",
		"go1.28-devel_abcdef Mon Jan": "tip",
	} {
		assert.Equal(t, want, hookmanifest.GoMinor(version), version)
	}
}
