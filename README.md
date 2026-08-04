# Datadog IAST for Go

This package provides Datadog-backed instrumentation for Interactive Application
Security Testing of Go applications. It uses `github.com/DataDog/dd-trace-go/v2`
and requires consumer applications to be compiled using
`github.com/DataDog/orchestrion`.

## Taint Tracking

Many of the functionality provided by this module relies on taint tracking:
- values (mostly `string`) obtained from untrusted _sources_ (e.g, HTTP request
  parameters) are _tainted_;
- the _taints_ are propagated as the values are combined or transformed through
  the processing of a request;
- _tainted_ values are _marked_ as they are passed through _sanitization_
  functions, as they can now be _trusted_ for certain specific operations;
- finally, when a _tainted_ value is fed into a dangerous _sink_ (e.g, an SQL
  query execution function), and no corresponding safety _mark_ has been placed,
  a _vulnerability_ is reported.

## Cost Control

Taint tracking has non-trivial associated cost; both in terms of memory and
time. This package makes all efforts possible to minimize the associated
overhead; and a Cost Control Engine is used to ensure the overall operating cost
of IAST in your applications can remain within acceptable parameters. In
particular, taint tracking is subject to a sampling decision.

## Runtime Configuration

Configuration is read from environment variables when the package is initialized.
Malformed values produce a warning and fall back to the documented default.
Integer values outside a documented range are clamped to that range.

Environment variable | Type | Default | Description
---|---|---:|---
`DD_IAST_ENABLED` | Boolean | `true` | Enables IAST.
`DD_IAST_REQUEST_SAMPLING` | Integer from `0` to `100` | `30` | Percentage of requests sampled for IAST analysis.
`DD_IAST_MAX_CONCURRENT_REQUESTS` | Non-negative integer | `2` | Maximum number of requests that IAST processes concurrently.
`DD_IAST_VULNERABILITIES_PER_REQUEST` | Integer greater than or equal to `1` | `2` | Maximum number of vulnerabilities reported for one request.
`DD_IAST_DEDUPLICATION_ENABLED` | Boolean | `true` | Enables vulnerability deduplication.
`DD_IAST_REDACTION_ENABLED` | Boolean | `true` | Enables sensitive data redaction.
`DD_IAST_REDACTION_NAME_PATTERN` | String | Empty | Pattern used to identify source names that must be redacted.
`DD_IAST_REDACTION_VALUE_PATTERN` | String | Empty | Pattern used to identify source values that must be redacted.
`DD_IAST_TRUNCATION_MAX_VALUE` | Non-negative integer | `250` | Maximum source value length before truncation.
`DD_IAST_MAX_RANGE_COUNT` | Non-negative integer | `10` | Maximum number of taint ranges retained for one value.
`DD_IAST_TELEMETRY_VERBOSITY` | `OFF`, `MANDATORY`, `INFORMATION`, or `DEBUG` | `INFORMATION` | Sets IAST telemetry verbosity.
`DD_IAST_DB_ROWS_TO_TAIN` | Non-negative integer | `1` | Number of database rows tainted for each request.
`DD_IAST_STACK_TRACE_ENABLED` | Boolean | `true` | Includes stack traces in vulnerability reports.

> [!NOTE]
> Boolean values are parsed using [`strconv.ParseBool`](https://pkg.go.dev/strconv#ParseBool),
> which accepts the following values:
> - Truthy: `1`, `t`, `T`, `TRUE`, `true`, `True`
> - Falsy: `0`, `f`, `F`, `FALSE`, `false`, `False`

## Vulnerability Types

Name | Severity | Implemented
---|---|:---:
Admin console active | Low | :x:
Code injection | High | :x:
Command injection | Critical | :x:
Default application deployed | Low | :x:
Default HTML escape invalid | High | :x:
Directory listing leak | High | :x:
Email HTML injection | Medium | :x:
Hardcoded password | High | :x:
Hardcoded secrets | High | :x:
Header injection | High | :x:
HSTS header missing | Low | :x:
Insecure auth protocol | Medium | :x:
Insecure cookies | Low | :x:
Insecure JSP layout | Medium | :x:
LDAP injection | High | :x:
MongoDB injection | Critical | :x:
No `HttpOnly` cookie | Low | :x:
No `SameSite` cookie | Low | :x:
Path traversal | High | :x:
Reflection injection | Medium | :x:
Server-side request forgery | Critical | :x:
Session rewriting | Medium | :x:
Session timeout | Low | :x:
SQL injection | Critical | :x:
Stacktrace leak | Medium | :x:
Template injection | High | :x:
Trust boundary violation | High | :x:
Untrusted deserialization | Medium | :x:
Un-validated redirect | High | :x:
Verb tampering | High | :x:
Weak cipher | Medium | :white_check_mark: `github.com/DataDog/dd-iast-go/iast/crypto/cipher`
Weak hash | Medium | :white_check_mark: `github.com/DataDog/dd-iast-go/iast/crypto/hash`
Weak randomness | Low | :x:
`X-Content-Type-Options` header missing | Low | :x:
`X-XSS-Protection` header disabled | Low | :x:
XPath injection | High | :x:
Cross-Site Scripting | High | :x:
