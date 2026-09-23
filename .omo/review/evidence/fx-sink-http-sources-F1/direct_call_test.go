package reviewhttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// This is an ordinary directly called helper, not an http.Handler.
// Its contract explicitly includes mutating the caller's header map.
func stampDispatchResult(w http.ResponseWriter, req *http.Request) {
	req.Header.Set("X-Result", "visible")
	w.WriteHeader(http.StatusNoContent)
}

func TestHeaderDirectFunction(t *testing.T) {
	// Given a request whose mutation is part of this helper's contract.
	req := httptest.NewRequest(http.MethodGet, "/dispatch", nil)
	req.Header.Set("X-Input", "external-value")
	alias := req.Header

	// When calling the function directly, outside net/http server dispatch.
	recorder := httptest.NewRecorder()
	stampDispatchResult(recorder, req)

	// Then the caller observes the documented mutation.
	t.Logf("woven=%t direct_function_status=%d caller=%q",
		built.WithOrchestrion, recorder.Code, alias.Get("X-Result"))
	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.Equal(t, "visible", alias.Get("X-Result"))
}
