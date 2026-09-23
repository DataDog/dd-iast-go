package io_test

import (
	"io"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
	"github.com/stretchr/testify/require"
)

// lexIdent is ordinary customer lexer code: it grows a token by reslicing.
func lexIdent(data []byte, start int) []byte {
	tok := data[start : start+1]
	for start+len(tok) < len(data) && data[start+len(tok)] != ' ' {
		tok = tok[:len(tok)+1]
	}
	return tok
}

func TestFxWovenReadAllGrowingToken(t *testing.T) {
	if !built.WithOrchestrion {
		t.Skip("orchestrion is not enabled, use `go tool orchestrion go test`")
	}
	ctx, _ := activeContext(t)
	input := &errorReader{data: []byte("name=alice'--OR-1=1 tail"), terminal: io.EOF}
	require.True(t, request.BindReader(ctx, input))
	body, err := io.ReadAll(input)
	require.NoError(t, err)
	t.Logf("body=%q len=%d cap=%d tainted=%v", body, len(body), cap(body), taint.IsTaintedBytes(body))
	require.True(t, taint.IsTaintedBytes(body), "precondition: io.ReadAll body source")

	// Control: in-length slice (distinct key from the lexed token), assigned
	// conversion, then concatenation of the string.
	value := body[5:18]
	ctlName := string(value)
	ctlQuery := "SELECT * FROM users WHERE name='" + ctlName + "'"
	t.Logf("control value=%q bytes=%v name=%v query=%v", value, taint.IsTaintedBytes(value), taint.IsTaintedString(ctlName), taint.IsTaintedString(ctlQuery))
	require.True(t, taint.IsTaintedString(ctlQuery), "control must stay tainted")

	// Customer lexer: the token is grown by tok = tok[:len(tok)+1].
	tok := lexIdent(body, 5)
	name := string(tok)
	query := "SELECT * FROM users WHERE name='" + name + "'"
	t.Logf("lexed tok=%q len=%d cap=%d bytes=%v name=%v query=%v", tok, len(tok), cap(tok), taint.IsTaintedBytes(tok), taint.IsTaintedString(name), taint.IsTaintedString(query))
	require.Equal(t, "alice'--OR-1=1", name)
	require.True(t, taint.IsTaintedBytes(tok), "FX-REPRO: grown token lost provenance")
	require.True(t, taint.IsTaintedString(query), "FX-REPRO: SQL query built from grown token is untainted")
}
