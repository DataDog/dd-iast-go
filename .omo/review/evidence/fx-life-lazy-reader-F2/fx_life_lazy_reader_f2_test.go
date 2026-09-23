package http_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

type fxMixedBodyObservation struct {
	Value  string        `json:"value"`
	Ranges []taint.Range `json:"ranges"`
}

func fxMixedBodyEndpoint(w http.ResponseWriter, req *http.Request) {
	data, err := io.ReadAll(io.MultiReader(strings.NewReader("trusted-"), req.Body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	got := fxMixedBodyObservation{Value: string(data)}
	taint.VisitBytes(data, func(r taint.Range) bool {
		got.Ranges = append(got.Ranges, r)
		return true
	})
	_ = json.NewEncoder(w).Encode(got)
}

// This test passes only when the woven production HTTP source incorrectly
// attributes the server-independent prefix to the request body.
func TestReviewFXMixedMultiReaderAttributesTrustedPrefixToRequestBody(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("requires `go tool orchestrion go test`")
	}
	testConfig(t, 100, 64)
	server := httptest.NewServer(http.HandlerFunc(fxMixedBodyEndpoint))
	defer server.Close()

	response, err := server.Client().Post(
		server.URL, "application/octet-stream", strings.NewReader("attacker"),
	)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusOK, response.StatusCode)

	var got fxMixedBodyObservation
	require.NoError(t, json.NewDecoder(response.Body).Decode(&got))
	require.Equal(t, "trusted-attacker", got.Value)
	require.Len(t, got.Ranges, 1)
	r := got.Ranges[0]
	require.Equal(t, uint32(0), r.Start)
	require.Equal(t, uint32(len(got.Value)), r.Length)
	require.Equal(t, taint.OriginHttpRequestBody, r.Source.Origin)
	require.Equal(t, got.Value, r.Source.Value)
	require.Less(t, r.Start, uint32(len("trusted-")))
	t.Logf(
		"OBSERVED false provenance: range=[%d,%d) origin=%v source=%q trustedPrefix=%q",
		r.Start, r.Start+r.Length, r.Source.Origin, r.Source.Value, got.Value[:len("trusted-")],
	)
}
