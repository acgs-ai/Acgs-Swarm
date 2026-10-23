// Package jcs provides a bounded, independent RFC 8785 reference for testing
// APCC-CJ1's subset conformance. It is not used by the certificate verifier.
package jcs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	MaxBytes = 2 * 1024 * 1024
	MaxDepth = 128
)

// Canonicalize accepts JSON with whitespace and returns RFC 8785 bytes.
// Unlike APCC-CJ1 it permits numbers, literals and non-ASCII property names,
// and preserves Unicode normalization. Duplicate names and invalid Unicode
// are rejected before encoding/json can replace or discard them.
func Canonicalize(raw []byte) ([]byte, error) {
	if len(raw) > MaxBytes {
		return nil, fmt.Errorf("JCS input exceeds byte limit")
	}
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return nil, fmt.Errorf("invalid JSON or UTF-8")
	}
	if err := validateSurrogates(raw); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	result, err := value(d, 1)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON data")
	}
	return result, nil
}

func value(d *json.Decoder, depth int) ([]byte, error) {
	if depth > MaxDepth {
		return nil, fmt.Errorf("JCS input exceeds depth limit")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch v := token.(type) {
	case json.Delim:
		var out bytes.Buffer
		out.WriteRune(rune(v))
		var close json.Delim
		switch v {
		case '{':
			close = '}'
			members := map[string][]byte{}
			var keys []string
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("invalid object property")
				}
				if _, duplicate := members[key]; duplicate {
					return nil, fmt.Errorf("duplicate object property")
				}
				child, err := value(d, depth+1)
				if err != nil {
					return nil, err
				}
				keys = append(keys, key)
				members[key] = child
			}
			slices.SortFunc(keys, func(a, b string) int {
				return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
			})
			for i, key := range keys {
				if i > 0 {
					out.WriteByte(',')
				}
				out.WriteString(quote(key))
				out.WriteByte(':')
				out.Write(members[key])
			}
		case '[':
			close = ']'
			for i := 0; d.More(); i++ {
				child, err := value(d, depth+1)
				if err != nil {
					return nil, err
				}
				if i > 0 {
					out.WriteByte(',')
				}
				out.Write(child)
			}
		default:
			return nil, fmt.Errorf("unexpected delimiter")
		}
		end, err := d.Token()
		if err != nil {
			return nil, err
		}
		if end != close {
			return nil, fmt.Errorf("unexpected closing delimiter")
		}
		out.WriteRune(rune(close))
		return out.Bytes(), nil
	case string:
		return []byte(quote(v)), nil
	case float64:
		return number(v)
	case bool, nil:
		return json.Marshal(v)
	default:
		return nil, fmt.Errorf("unsupported JSON value")
	}
}

func number(v float64) ([]byte, error) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil, fmt.Errorf("non-finite JCS number")
	}
	if v == 0 {
		return []byte("0"), nil
	}
	// Go's JSON float encoder uses ES6 fixed/exponential thresholds and
	// shortest-roundtrip binary64 formatting. Appendix B locks that contract.
	return json.Marshal(v)
}

func quote(v string) string {
	var out strings.Builder
	out.WriteByte('"')
	for _, r := range v {
		switch r {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteRune(r)
		case '\b':
			out.WriteString(`\b`)
		case '\t':
			out.WriteString(`\t`)
		case '\n':
			out.WriteString(`\n`)
		case '\f':
			out.WriteString(`\f`)
		case '\r':
			out.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return out.String()
}

// The caller has already checked JSON syntax. Scan every string (including
// property names) before encoding/json silently replaces unpaired surrogates.
func validateSurrogates(raw []byte) error {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		i++
		for raw[i] != '"' {
			if raw[i] != '\\' {
				i++
				continue
			}
			i++
			if raw[i] != 'u' {
				i++
				continue
			}
			unit, _ := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
			i += 5
			if unit >= 0xdc00 && unit <= 0xdfff {
				return fmt.Errorf("unpaired low surrogate")
			}
			if unit >= 0xd800 && unit <= 0xdbff {
				if i+6 > len(raw) || raw[i] != '\\' || raw[i+1] != 'u' {
					return fmt.Errorf("unpaired high surrogate")
				}
				low, err := strconv.ParseUint(string(raw[i+2:i+6]), 16, 16)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return fmt.Errorf("invalid surrogate pair")
				}
				i += 6
			}
		}
	}
	return nil
}
