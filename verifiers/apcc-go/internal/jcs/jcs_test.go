package jcs

import (
	"bytes"
	"math"
	"strconv"
	"strings"
	"testing"
)

// All 26 rows from RFC 8785 Appendix B, including the two forbidden values.
// Source: https://www.rfc-editor.org/rfc/rfc8785.html#appendix-B
// IEEE 754 bits are inputs, not values reconstructed from expected decimals.
func TestRFC8785AppendixB(t *testing.T) {
	tests := []struct {
		bits uint64
		want string
	}{
		{0x0000000000000000, "0"},
		{0x8000000000000000, "0"},
		{0x0000000000000001, "5e-324"},
		{0x8000000000000001, "-5e-324"},
		{0x7fefffffffffffff, "1.7976931348623157e+308"},
		{0xffefffffffffffff, "-1.7976931348623157e+308"},
		{0x4340000000000000, "9007199254740992"},
		{0xc340000000000000, "-9007199254740992"},
		{0x4430000000000000, "295147905179352830000"},
		{0x7fffffffffffffff, ""},
		{0x7ff0000000000000, ""},
		{0x44b52d02c7e14af5, "9.999999999999997e+22"},
		{0x44b52d02c7e14af6, "1e+23"},
		{0x44b52d02c7e14af7, "1.0000000000000001e+23"},
		{0x444b1ae4d6e2ef4e, "999999999999999700000"},
		{0x444b1ae4d6e2ef4f, "999999999999999900000"},
		{0x444b1ae4d6e2ef50, "1e+21"},
		{0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"},
		{0x3eb0c6f7a0b5ed8d, "0.000001"},
		{0x41b3de4355555553, "333333333.3333332"},
		{0x41b3de4355555554, "333333333.33333325"},
		{0x41b3de4355555555, "333333333.3333333"},
		{0x41b3de4355555556, "333333333.3333334"},
		{0x41b3de4355555557, "333333333.33333343"},
		{0xbecbf647612f3696, "-0.0000033333333333333333"},
		{0x43143ff3c1cb0959, "1424953923781206.2"},
	}
	for _, tt := range tests {
		t.Run(strconv.FormatUint(tt.bits, 16), func(t *testing.T) {
			v := math.Float64frombits(tt.bits)
			got, err := number(v)
			if tt.want == "" {
				if err == nil {
					t.Fatalf("non-finite input accepted: %q", got)
				}
				return
			}
			if err != nil || string(got) != tt.want {
				t.Fatalf("number = %q, %v; want %q", got, err, tt.want)
			}
			// Exercise the public JSON parser/serializer path as well.
			input := strconv.FormatFloat(v, 'g', -1, 64)
			got, err = Canonicalize([]byte(input))
			if err != nil || string(got) != tt.want {
				t.Fatalf("Canonicalize(%q) = %q, %v; want %q", input, got, err, tt.want)
			}
		})
	}
}

func TestRFC8785ExamplesAndBoundaries(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{
			"section 3.2.2 sample",
			`{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}`,
			`{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`,
		},
		{
			"section 3.2.3 UTF16 property order",
			`{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`,
			"{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}",
		},
		{"recursive sorting and array order", `{"z":[{"z":0,"a":1},3,2],"a":{}}`, `{"a":{},"z":[{"a":1,"z":0},3,2]}`},
		{"property prefixes", `{"ab":0,"aa":1,"a":2,"":3}`, `{"":3,"a":2,"aa":1,"ab":0}`},
		{"negative zero", `[-0,-0.0,-0e30]`, `[0,0,0]`},
		{"exponent thresholds", `[1e-7,1e-6,1e20,1e21,-1e-7,-1e-6,-1e20,-1e21]`, `[1e-7,0.000001,100000000000000000000,1e+21,-1e-7,-0.000001,-100000000000000000000,-1e+21]`},
		{"no HTML or line-separator escaping", `"\u003c\u003e\u0026\/\u2028\u2029"`, "\"<>&/\u2028\u2029\""},
		{"preserve decomposed Unicode", `"e\u0301"`, "\"e\u0301\""},
		{"valid replacement character", `"\ufffd"`, "\"\ufffd\""},
		{"literal surrogate escape text", `"\\ud800"`, `"\\ud800"`},
		{"valid surrogate boundaries", `["\ud800\udc00","\udbff\udfff"]`, "[\"\U00010000\",\"\U0010ffff\"]"},
		{"whitespace", " \t { \"b\" : false, \"a\" : null } \r\n", `{"a":null,"b":false}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tt.input))
			if err != nil || string(got) != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
			again, err := Canonicalize(got)
			if err != nil || !bytes.Equal(again, got) {
				t.Fatalf("canonicalization not idempotent: %q, %v", again, err)
			}
		})
	}
}

func TestRejectInvalidJCS(t *testing.T) {
	tests := map[string][]byte{
		"duplicate":             []byte(`{"a":1,"a":2}`),
		"escaped duplicate":     []byte(`{"a":1,"\u0061":2}`),
		"nested duplicate":      []byte(`[{"a":null,"a":false}]`),
		"lone high":             []byte(`"\ud800"`),
		"lone low":              []byte(`"\udfff"`),
		"high followed by BMP":  []byte(`"\ud800\u0041"`),
		"high followed by high": []byte(`"\ud800\ud800"`),
		"surrogate property":    []byte(`{"\ud800":"x"}`),
		"invalid UTF8":          {'"', 0xff, '"'},
		"UTF8 surrogate":        {'"', 0xed, 0xa0, 0x80, '"'},
		"BOM":                   {0xef, 0xbb, 0xbf, '[', ']'},
		"overflow":              []byte(`1e9999`),
		"negative overflow":     []byte(`-1e9999`),
		"NaN":                   []byte(`NaN`),
		"Infinity":              []byte(`Infinity`),
		"two values":            []byte(`{} []`),
		"trailing comma":        []byte(`[1,]`),
		"invalid escape":        []byte(`"\x00"`),
		"empty":                 {},
		"byte limit":            []byte(`"` + strings.Repeat("x", MaxBytes) + `"`),
		"depth limit":           []byte(strings.Repeat("[", MaxDepth) + "0" + strings.Repeat("]", MaxDepth)),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if output, err := Canonicalize(input); err == nil {
				t.Fatalf("accepted invalid input as %q", output)
			}
		})
	}
	if _, err := number(math.Inf(-1)); err == nil {
		t.Fatal("accepted negative infinity")
	}
}

func TestAllASCIIControls(t *testing.T) {
	input := `"`
	want := `"`
	for r := 0; r < 32; r++ {
		hex := strconv.FormatInt(int64(r), 16)
		if len(hex) == 1 {
			hex = "0" + hex
		}
		escape := `\u00` + hex
		input += escape
		switch r {
		case 8:
			want += `\b`
		case 9:
			want += `\t`
		case 10:
			want += `\n`
		case 12:
			want += `\f`
		case 13:
			want += `\r`
		default:
			want += escape
		}
	}
	input += `"`
	want += `"`
	got, err := Canonicalize([]byte(input))
	if err != nil || string(got) != want {
		t.Fatalf("got %q, %v; want %q", got, err, want)
	}
}

func FuzzCanonicalize(f *testing.F) {
	for _, seed := range []string{
		`{"a":"x"}`, `"\ud800"`, `"\ud800\udc00"`,
		`"\\\"\\ud800"`, `[1e-7,-0,true,null]`, `{"a":1,"a":2}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		output, err := Canonicalize(input)
		if err != nil {
			return
		}
		again, err := Canonicalize(output)
		if err != nil || !bytes.Equal(output, again) {
			t.Fatalf("not idempotent: %q -> %q, %v", output, again, err)
		}
	})
}
