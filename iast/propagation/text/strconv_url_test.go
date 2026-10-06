// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package text_test

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The coarse transforms of plan section 6.3. PR #39 gave a coarse range of
// the whole output; here also the whole output is tainted, and the derived
// entry gives the first source of the input (plan section 9.2).

func TestStrconvQuote(t *testing.T) {
	a := begin(t)
	value := source(t, a, "q", "it's \"x\"\n")
	input := "<" + value
	for name, quote := range map[string]func(string) string{
		"Quote":          strconv.Quote,
		"QuoteToASCII":   strconv.QuoteToASCII,
		"QuoteToGraphic": strconv.QuoteToGraphic,
	} {
		t.Run(name, func(t *testing.T) {
			got := quote(input)
			require.Equal(t, quote(strings.Clone(input)), got)
			require.Equal(t, []span{{0, len(got)}}, stringSpans(got))
			require.Equal(t, []string{"0-" + strconv.Itoa(len(got)) + "=q"}, attributed(t, a, got))
			query := "SELECT " + got
			require.Equal(t, []string{"7-" + strconv.Itoa(len(query)) + "=q"}, attributed(t, a, query))
		})
	}

	t.Run("AppendQuote is not hooked", func(t *testing.T) {
		got := strconv.AppendQuote(make([]byte, 0, 64), input)
		require.Empty(t, bytesSpans(got), "fmt passes its scratch array to appendQuotedWith (plan section 6.3)")
	})

	t.Run("clean input", func(t *testing.T) {
		require.Empty(t, stringSpans(strconv.Quote(strings.Clone("clean"))))
	})
}

func TestStrconvUnquote(t *testing.T) {
	a := begin(t)

	t.Run("no escape returns a part of the input", func(t *testing.T) {
		value := source(t, a, "plain", `"plain value"`)
		got, err := strconv.Unquote(value)
		require.NoError(t, err)
		require.Equal(t, "plain value", got)
		require.Equal(t, []span{{0, 11}}, stringSpans(got))
		require.Equal(t, []string{"0-11=plain"}, attributed(t, a, got))
	})

	t.Run("escapes are coarse", func(t *testing.T) {
		value := source(t, a, "escaped", `"a\tb\u00e9\"c"`)
		got, err := strconv.Unquote(value)
		require.NoError(t, err)
		require.Equal(t, "a\tbé\"c", got)
		require.Equal(t, []span{{0, len(got)}}, stringSpans(got))
		require.Equal(t, []string{"0-" + strconv.Itoa(len(got)) + "=escaped"}, attributed(t, a, got))
	})

	t.Run("raw and char literals", func(t *testing.T) {
		raw := source(t, a, "raw", "`raw\\n`")
		got, err := strconv.Unquote(raw)
		require.NoError(t, err)
		require.Equal(t, `raw\n`, got)
		require.Equal(t, []span{{0, 5}}, stringSpans(got))
		char := source(t, a, "char", `'\n'`)
		got, err = strconv.Unquote(char)
		require.NoError(t, err)
		require.Equal(t, "\n", got)
	})

	t.Run("errors are kept", func(t *testing.T) {
		for _, value := range []string{`"unterminated`, `"bad \q"`, `'ab'`, `"a"b`} {
			v := source(t, a, "bad", value)
			got, err := strconv.Unquote(v)
			want, wantErr := strconv.Unquote(strings.Clone(value))
			require.Equal(t, want, got)
			require.Equal(t, wantErr, err)
			require.True(t, errors.Is(err, strconv.ErrSyntax), "%q", value)
		}
	})

	t.Run("QuotedPrefix returns a part of the input", func(t *testing.T) {
		value := "<" + source(t, a, "prefix", `"a\tb" tail`)
		got, err := strconv.QuotedPrefix(value[1:])
		require.NoError(t, err)
		require.Equal(t, `"a\tb"`, got)
		require.True(t, sameData(value[1:], got))
		require.Equal(t, []span{{0, 6}}, stringSpans(got))
	})
}

func TestURLEscape(t *testing.T) {
	a := begin(t)
	value := source(t, a, "q", "a b&c/é")
	input := "x" + value

	for name, escape := range map[string]func(string) string{
		"QueryEscape": url.QueryEscape,
		"PathEscape":  url.PathEscape,
	} {
		t.Run(name, func(t *testing.T) {
			got := escape(input)
			require.Equal(t, escape(strings.Clone(input)), got)
			require.Equal(t, []span{{0, len(got)}}, stringSpans(got))
			require.Equal(t, []string{"0-" + strconv.Itoa(len(got)) + "=q"}, attributed(t, a, got))
		})
	}

	t.Run("spaces only (query)", func(t *testing.T) {
		got := url.QueryEscape("x" + source(t, a, "spaces", "a b c"))
		require.Equal(t, "xa+b+c", got)
		require.Equal(t, []span{{0, 6}}, stringSpans(got))
	})

	t.Run("nothing to escape returns the input", func(t *testing.T) {
		safe := "x" + source(t, a, "safe", "abc")
		got := url.QueryEscape(safe)
		require.True(t, sameData(safe, got))
		require.Equal(t, []span{{1, 4}}, stringSpans(got))
	})

	t.Run("Values.Encode", func(t *testing.T) {
		got := url.Values{"k": {input}}.Encode()
		require.Equal(t, "k=xa+b%26c%2F%C3%A9", got)
		require.Equal(t, []span{{2, len(got)}}, stringSpans(got))
		require.Equal(t, []string{"2-" + strconv.Itoa(len(got)) + "=q"}, attributed(t, a, got))
	})

	t.Run("URL.String", func(t *testing.T) {
		u := &url.URL{Scheme: "http", Host: "h", Path: "/" + value}
		got := u.String()
		require.Equal(t, "http://h/a%20b&c/%C3%A9", got)
		require.NotEmpty(t, stringSpans(got))
	})
}

func TestURLUnescape(t *testing.T) {
	a := begin(t)
	value := source(t, a, "q", "a%20b+c%27")

	for name, test := range map[string]struct {
		unescape func(string) (string, error)
		want     string
	}{
		"QueryUnescape": {url.QueryUnescape, "a b c'"},
		"PathUnescape":  {url.PathUnescape, "a b+c'"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := test.unescape(value)
			require.NoError(t, err)
			require.Equal(t, test.want, got)
			require.Equal(t, []span{{0, len(got)}}, stringSpans(got))
			require.Equal(t, []string{"0-6=q"}, attributed(t, a, got))
			query := "WHERE x = '" + got + "'"
			require.Equal(t, []string{"11-17=q"}, attributed(t, a, query))
		})
	}

	t.Run("nothing to unescape returns the input", func(t *testing.T) {
		plain := "x" + source(t, a, "plain", "abc")
		got, err := url.QueryUnescape(plain)
		require.NoError(t, err)
		require.True(t, sameData(plain, got))
		require.Equal(t, []span{{1, 4}}, stringSpans(got))
	})

	t.Run("errors keep the part of the input", func(t *testing.T) {
		bad := "x" + source(t, a, "bad", "a%zzb")
		got, err := url.QueryUnescape(bad)
		_, want := url.QueryUnescape(strings.Clone("xa%zzb"))
		require.Empty(t, got)
		require.Equal(t, want, err)
		var escapeErr url.EscapeError
		require.ErrorAs(t, err, &escapeErr)
		require.Equal(t, "%zz", string(escapeErr))
		require.True(t, sameData(bad[2:], string(escapeErr)), "the error holds a part of the input, as in the original")
		require.Equal(t, []span{{0, 3}}, stringSpans(string(escapeErr)))
	})

	t.Run("ParseQuery", func(t *testing.T) {
		values, err := url.ParseQuery("k=" + value + "&plain=" + source(t, a, "plain2", "abc"))
		require.NoError(t, err)
		got := values.Get("k")
		require.Equal(t, "a b c'", got)
		require.Equal(t, []span{{0, 6}}, stringSpans(got))
		require.Equal(t, []string{"0-6=q"}, attributed(t, a, got))
		plain := values.Get("plain")
		require.Equal(t, []span{{0, 3}}, stringSpans(plain))
	})

	t.Run("url.Parse host error", func(t *testing.T) {
		host := source(t, a, "host", "a b")
		_, err := url.Parse("http://" + host + "/")
		_, want := url.Parse("http://a b/")
		require.Equal(t, want.Error(), err.Error())
	})
}
