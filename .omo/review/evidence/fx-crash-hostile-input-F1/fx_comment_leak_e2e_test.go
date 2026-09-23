// fx-crash-hostile-input-F1: woven e2e check. HTTP query param reaches the
// database/sql sink through a woven library call; asserts the shared-corpus
// expectation that the application-owned SQL comment body is redacted in the
// evidence payload attached to the span.
package testapp_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/model"
	testapp "github.com/DataDog/dd-iast-go/testapps/integration"
	"github.com/stretchr/testify/require"
)

func fxRequireNoClearSecret(t *testing.T, event model.Event, secret string) {
	t.Helper()
	require.NotEmpty(t, event.Vulnerabilities, "no SQLi finding was reported")
	for _, vulnerability := range event.Vulnerabilities {
		if vulnerability.Evidence == nil {
			continue
		}
		for _, part := range vulnerability.Evidence.ValueParts {
			t.Logf("part: %+v", part)
			if !part.Redacted && strings.Contains(part.Value, secret) {
				t.Errorf("secret %q appears unredacted in the evidence that leaves the process", secret)
			}
		}
	}
}

func TestFxSQLCommentTailRedactedEndToEnd(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		email := r.URL.Query().Get("email")
		query := testapp.BuildFxLineCommentQuery(email)
		_, _ = db.ExecContext(ctx, query)
	}, url.Values{"email": {"' OR TRUE --"}})
	fxRequireNoClearSecret(t, event, testapp.FxPasswordHash)
}

func TestFxSQLBlockCommentRedactedEndToEnd(t *testing.T) {
	requireWoven(t)
	db := openDB(t)
	event := requestEvent(t, func(ctx context.Context, r *http.Request) {
		email := r.URL.Query().Get("email")
		query := testapp.BuildFxBlockCommentQuery(email)
		_, _ = db.ExecContext(ctx, query)
	}, url.Values{"email": {"' OR TRUE --"}})
	fxRequireNoClearSecret(t, event, testapp.FxPasswordHash)
}
