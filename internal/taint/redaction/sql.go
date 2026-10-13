// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package redaction

import (
	"github.com/DataDog/go-sqllexer"
)

var sqlDialects = [...]sqllexer.DBMSType{
	"",
	sqllexer.DBMSMySQL,
	sqllexer.DBMSPostgres,
	sqllexer.DBMSOracle,
	sqllexer.DBMSSQLServer,
	sqllexer.DBMSSnowflake,
}

// AnalyzeSQL finds literal bodies using the bounded union of supported SQL
// dialect tokenizations. Delimiters remain visible in evidence.
func AnalyzeSQL(query string) Analysis {
	if len(query) > MaxAnalyzerBytes {
		return Analysis{Status: AnalysisOversized}
	}
	quoteIntervals, quoteSpans, ok := scanOracleQuotes(query)
	if !ok {
		return Analysis{Status: AnalysisDropped}
	}
	intervals := make([]Interval, 0, len(sqlDialects)*16+len(quoteIntervals))
	intervals = append(intervals, quoteIntervals...)
	for _, dialect := range sqlDialects {
		tokens := 0
		dialectIntervals := 0
		segmentStart := 0
		for _, span := range quoteSpans {
			if !scanSQLSegment(query[segmentStart:span.start], segmentStart, dialect, &tokens, &dialectIntervals, &intervals) {
				return Analysis{Status: AnalysisDropped}
			}
			segmentStart = span.end
		}
		if !scanSQLSegment(query[segmentStart:], segmentStart, dialect, &tokens, &dialectIntervals, &intervals) {
			return Analysis{Status: AnalysisDropped}
		}
	}
	intervals = canonicalIntervals(intervals)
	if len(intervals) > MaxSensitiveIntervals {
		return Analysis{Status: AnalysisDropped}
	}
	return Analysis{Value: query, Sensitive: intervals}
}

func scanSQLSegment(segment string, offset int, dialect sqllexer.DBMSType, tokens, dialectIntervals *int, intervals *[]Interval) bool {
	lexer := sqllexer.New(segment, sqllexer.WithDBMS(dialect))
	position := 0
	for {
		if *tokens >= maxAnalyzerTokens {
			return false
		}
		*tokens++
		token := lexer.Scan()
		if token == nil {
			return false
		}
		if token.Type == sqllexer.EOF {
			return position == len(segment)
		}
		if token.Type == sqllexer.ERROR || len(token.Value) == 0 || len(token.Value) > len(segment)-position || segment[position:position+len(token.Value)] != token.Value {
			return false
		}
		if interval, sensitive := sqlSensitiveToken(token.Type, offset+position, token.Value); sensitive {
			if *dialectIntervals >= MaxSensitiveIntervals {
				return false
			}
			*intervals = append(*intervals, interval)
			*dialectIntervals++
		}
		position += len(token.Value)
	}
}

func sqlSensitiveToken(tokenType sqllexer.TokenType, start int, value string) (Interval, bool) {
	switch tokenType {
	case sqllexer.STRING, sqllexer.INCOMPLETE_STRING:
		low, high := start, start+len(value)
		if len(value) > 0 && (value[0] == '\'' || value[0] == '"') {
			low++
			if len(value) > 1 && value[len(value)-1] == value[0] {
				high--
			}
		}
		return checkedInterval(low, high)
	case sqllexer.DOLLAR_QUOTED_STRING, sqllexer.DOLLAR_QUOTED_FUNCTION:
		return dollarQuoteBody(start, value)
	case sqllexer.NUMBER, sqllexer.BOOLEAN, sqllexer.NULL:
		return checkedInterval(start, start+len(value))
	default:
		return Interval{}, false
	}
}

type byteSpan struct {
	start int
	end   int
}

func scanOracleQuotes(query string) ([]Interval, []byteSpan, bool) {
	intervals := make([]Interval, 0, 2)
	spans := make([]byteSpan, 0, 2)
	for index := 0; index+2 < len(query); index++ {
		if (query[index] != 'q' && query[index] != 'Q') || query[index+1] != '\'' || index > 0 && isSQLIdentifierByte(query[index-1]) {
			continue
		}
		open := query[index+2]
		if isSQLIdentifierByte(open) || open == '\'' || open == '"' || open == ' ' || open == '\t' || open == '\r' || open == '\n' {
			continue
		}
		closing := open
		switch open {
		case '[':
			closing = ']'
		case '{':
			closing = '}'
		case '(':
			closing = ')'
		case '<':
			closing = '>'
		}
		bodyStart := index + 3
		bodyEnd := len(query)
		spanEnd := len(query)
		for cursor := bodyStart; cursor+1 < len(query); cursor++ {
			if query[cursor] == closing && query[cursor+1] == '\'' {
				bodyEnd = cursor
				spanEnd = cursor + 2
				break
			}
		}
		if spanEnd < len(query) && isSQLIdentifierByte(query[spanEnd]) {
			continue
		}
		if bodyEnd > bodyStart {
			interval, _ := checkedInterval(bodyStart, bodyEnd)
			intervals = append(intervals, interval)
			spans = append(spans, byteSpan{start: index, end: spanEnd})
			if len(intervals) > MaxSensitiveIntervals {
				return nil, nil, false
			}
		}
		index = spanEnd - 1
	}
	return intervals, spans, true
}

func isSQLIdentifierByte(value byte) bool {
	return value >= 0x80 || value == '_' || value == '$' || value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func dollarQuoteBody(start int, value string) (Interval, bool) {
	if len(value) < 2 || value[0] != '$' {
		return Interval{}, false
	}
	delimiterEnd := 1
	for delimiterEnd < len(value) && value[delimiterEnd] != '$' {
		delimiterEnd++
	}
	if delimiterEnd >= len(value) {
		return checkedInterval(start, start+len(value))
	}
	delimiter := value[:delimiterEnd+1]
	low := start + len(delimiter)
	high := start + len(value)
	if len(value) >= 2*len(delimiter) && value[len(value)-len(delimiter):] == delimiter {
		high -= len(delimiter)
	}
	return checkedInterval(low, high)
}

func checkedInterval(low, high int) (Interval, bool) {
	if low < 0 || high <= low || uint64(high) > uint64(^uint32(0)) {
		return Interval{}, false
	}
	return Interval{Start: uint32(low), Length: uint32(high - low)}, true
}
