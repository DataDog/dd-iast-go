package propagation_test

import (
	"bytes"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/iast/internal/propagationtest"
	"github.com/DataDog/dd-iast-go/taint"
	"github.com/DataDog/orchestrion/runtime/built"
)

func TestReviewByteWindowAliasesAndNamedType(t *testing.T) {
	if !built.WithOrchestrion {
		t.Fatal("review requires woven call sites")
	}
	tests := []struct {
		name string
		call func([]byte) []byte
		want string
	}{
		{"TrimSpace", testapp.BytesTrimSpace, "alpha,beta"},
		{"Fields", func(b []byte) []byte { return testapp.BytesFields(b)[0] }, "alpha,beta"},
		{"Split", func(b []byte) []byte { return testapp.BytesSplit(b, []byte(","))[0][2:] }, "alpha"},
		{"Cut", func(b []byte) []byte { before, _, _ := testapp.BytesCut(b, []byte(",")); return before[2:] }, "alpha"},
		{"NamedBytesTrimSpace", func(b []byte) []byte {
			return testapp.NamedBytesTrimSpace(testapp.NamedBytes(b))
		}, "alpha,beta"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := activeBytes(t, []byte("  alpha,beta "))
			got := tc.call(input)
			if string(got) != tc.want {
				t.Fatalf("result = %q, want %q", got, tc.want)
			}
			if unsafe.SliceData(got) != &input[2] {
				t.Fatalf("result is not an alias at offset 2")
			}
			if !taint.IsTaintedBytes(got) {
				t.Fatal("aliased result lost byte provenance")
			}
			got[0] = 'X'
			if input[2] != 'X' {
				t.Fatal("writing result did not change original input")
			}
		})
	}

	clean := []byte("  alpha,beta ")
	result := testapp.BytesTrimSpace(clean)
	if !bytes.Equal(result, []byte("alpha,beta")) || taint.IsTaintedBytes(result) {
		t.Fatalf("clean input tainted or changed: %q", result)
	}
}
