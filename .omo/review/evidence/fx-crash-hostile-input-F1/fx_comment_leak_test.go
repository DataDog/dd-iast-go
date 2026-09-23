// fx-crash-hostile-input-F1: independent verification of the SQL comment
// redaction gap. Written fresh for phase 3; asserts the shared-corpus
// expectation (comment bodies redacted) and reports what HEAD actually does.
package redaction

import (
	"strings"
	"testing"

	"github.com/DataDog/go-sqllexer"
)

const fxPasswordHash = "81dc9bdb52d04dc20036dbd8313ed055"

// fxExploitQuery is the canonical SQLi exploit shape: everything after the
// injected `--` is a comment containing the application-owned password hash.
const fxExploitQuery = `SELECT * FROM Users WHERE email = '` + `' OR TRUE --` + `' AND password = '` + fxPasswordHash + `' AND deletedAt IS NULL`

func TestFxSQLCommentTokensAreNotSensitive(t *testing.T) {
	// Mechanism check: prove the lexer really emits COMMENT / MULTILINE_COMMENT
	// tokens for these shapes, so they fall into sqlSensitiveToken's default.
	shapes := []struct {
		name     string
		query    string
		wantType sqllexer.TokenType
	}{
		{"line comment", "SELECT 1 -- " + fxPasswordHash + "\nFROM t", sqllexer.COMMENT},
		{"block comment", "SELECT 1 /* " + fxPasswordHash + " */", sqllexer.MULTILINE_COMMENT},
		{"exploit tail", "SELECT 1 -- ' AND password = '" + fxPasswordHash + "'", sqllexer.COMMENT},
	}
	for _, shape := range shapes {
		for _, dialect := range sqlDialects {
			lexer := sqllexer.New(shape.query, sqllexer.WithDBMS(dialect))
			var sawWant bool
			for {
				token := lexer.Scan()
				if token == nil || token.Type == sqllexer.EOF {
					break
				}
				if token.Type == shape.wantType && strings.Contains(token.Value, fxPasswordHash) {
					sawWant = true
				}
			}
			if !sawWant {
				t.Errorf("%s (dialect %q): no %v token carried the hash; tokens may be typed differently than claimed", shape.name, dialect, shape.wantType)
			}
		}
	}
}

func TestFxSQLCommentBodiesAreRedacted(t *testing.T) {
	cases := []struct {
		name  string
		query string
		secret string
	}{
		{"exploit line comment", fxExploitQuery, fxPasswordHash},
		{"plain line comment", "SELECT col -- " + fxPasswordHash, fxPasswordHash},
		{"block comment", "SELECT 1 /* token=" + fxPasswordHash + " */", fxPasswordHash},
		{"hash line comment", "SELECT col # " + fxPasswordHash, fxPasswordHash},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			analysis := AnalyzeSQL(testCase.query)
			if analysis.Status != AnalysisOK {
				t.Fatalf("status = %v", analysis.Status)
			}
			masked := maskSensitive(analysis)
			t.Logf("masked evidence: %q", masked)
			if strings.Contains(masked, testCase.secret) {
				t.Errorf("comment-body secret %q appears in clear in the evidence value; intervals=%#v", testCase.secret, analysis.Sensitive)
			}
			// Adversarial cross-check: the secret must also not be covered by any interval.
			for index := 0; ; index++ {
				if index+len(testCase.secret) > len(testCase.query) {
					break
				}
				if testCase.query[index:index+len(testCase.secret)] != testCase.secret {
					continue
				}
				covered := false
				for _, interval := range analysis.Sensitive {
					if uint32(index) >= interval.Start && uint32(index+len(testCase.secret)) <= interval.Start+interval.Length {
						covered = true
					}
				}
				if !covered {
					t.Errorf("secret at byte offset %d is not covered by any sensitive interval", index)
				}
				break
			}
		})
	}
}
