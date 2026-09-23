package propagation_test

import (
	"testing"

	"github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/evidence"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

type reviewF1Table struct{ name string }

func (table reviewF1Table) String() string { return table.name }

func TestReviewF1_StringerFieldReachesSQL_whenFormattedByApplication(t *testing.T) {
	// Given: an active request with a tainted SQL table fragment.
	require.True(t, built.WithOrchestrion)
	ctx := beginNativePropagation(t)
	tableName := nativeStringSource(t, ctx, "table", "users WHERE 1=1 --")

	// When: a root application package directly calls fmt.Sprintf with a Stringer.
	query := testapp.Sprintf("SELECT * FROM %v", reviewF1Table{name: tableName})

	// Then: the emitted table name must retain provenance at the SQL collector.
	_, status := evidence.CollectString(query, constants.VulnerabilityTypeSqlInjection)
	t.Logf("query=%q input_tainted=%t output_tainted=%t sql_collection=%v",
		query, taint.IsTaintedString(tableName), taint.IsTaintedString(query), status)
	require.Equal(t, "SELECT * FROM users WHERE 1=1 --", query)
	require.Equal(t, evidence.StatusCollected, status)
}
