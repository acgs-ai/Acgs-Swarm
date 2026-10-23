package cj1

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/acgs/apcc-go-verifier/internal/jcs"
)

// This is a subset-conformance bridge, not a claim that APCC accepts full JCS.
// JCS parses independently, using encoding/json rather than CJ1's parser.
func TestCJ1SubsetMatchesIndependentJCS(t *testing.T) {
	var controls string
	for r := rune(0); r < 32; r++ {
		controls += string(r)
	}
	values := []Value{
		Object{},
		Array{},
		"",
		controls,
		"<>&/\u2028\u2029",
		"é😀\U0010ffff",
		`literal \ud800 and \"`,
		Object{
			"z": Array{"last", Object{"b": "2", "a": "1"}, Array{}},
			"a": Object{"": controls, "aa": "value", "a": "first"},
		},
	}
	// Include every ASCII property name, including controls, DEL and quoting.
	keys := Object{}
	for r := rune(0); r < 128; r++ {
		keys[string(r)] = string(r)
	}
	values = append(values, keys)
	for i, value := range values {
		encoded, err := Encode(value)
		if err != nil {
			t.Fatalf("case %d: CJ1 Encode: %v", i, err)
		}
		if _, err := Parse(encoded, MaxPayloadBytes); err != nil {
			t.Fatalf("case %d: CJ1 Parse: %v", i, err)
		}
		reference, referenceErr := jcs.Canonicalize(encoded)
		if referenceErr != nil || !bytes.Equal(reference, encoded) {
			t.Fatalf("case %d: CJ1 %q differs from JCS %q: %v", i, encoded, reference, referenceErr)
		}
		// Independently serialize noncanonical JSON so this also tests the
		// reference's normalization, rather than only accepting CJ1 bytes.
		noncanonical, marshalErr := json.MarshalIndent(value, "", "  ")
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		reference, referenceErr = jcs.Canonicalize(noncanonical)
		if referenceErr != nil || !bytes.Equal(reference, encoded) {
			t.Fatalf("case %d: indented JSON yields %q, %v; want %q", i, reference, referenceErr, encoded)
		}
	}
}

func TestJCSReferenceDoesNotRelaxCJ1(t *testing.T) {
	tests := []struct {
		input, code string
	}{
		{`0`, "WRONG_JSON_TYPE"},
		{`true`, "WRONG_JSON_TYPE"},
		{`false`, "WRONG_JSON_TYPE"},
		{`null`, "WRONG_JSON_TYPE"},
		{`{"é":"value"}`, "UNKNOWN_FIELD"},
		{"\"e\u0301\"", "INVALID_UNICODE"},
	}
	for _, tt := range tests {
		if _, err := jcs.Canonicalize([]byte(tt.input)); err != nil {
			t.Fatalf("reference unexpectedly rejects %q: %v", tt.input, err)
		}
		if _, err := Parse([]byte(tt.input), MaxPayloadBytes); err == nil || err.Code != tt.code {
			t.Fatalf("CJ1 %q: got %v, want %s", tt.input, err, tt.code)
		}
	}
}
