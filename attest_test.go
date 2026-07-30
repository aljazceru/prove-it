package main

import (
	"encoding/hex"
	"testing"
)

func TestNormalizeReportData(t *testing.T) {
	canonical := "cf2b5bfe6f956590a7297b2d8fdd238b1a96eba3382c17ab9f5573b363dc57ad"

	cases := []struct {
		name string
		in   interface{}
		want string
		ok   bool
	}{
		{"lowercase hex 64", canonical, canonical, true},
		{"uppercase hex 64", "CF2B5BFE6F956590A7297B2D8FDD238B1A96EBA3382C17AB9F5573B363DC57AD", canonical, true},
		{"128-hex of ascii bytes", hex.EncodeToString([]byte(canonical)), canonical, true},
		{"array of ascii bytes", asciiToInterface(canonical), canonical, true},
		{"array of 32 raw bytes", bytesToInterface(toBytes(canonical)), canonical, true},
		{"non-hex string", "not hex at all", "", false},
		{"wrong length", "ab12", "", false},
		{"empty", "", "", false},
		{"null", nil, "", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := normalizeReportData(c.in)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if ok && got != c.want {
				t.Fatalf("got = %s, want %s", got, c.want)
			}
		})
	}
}

func TestDeepFind(t *testing.T) {
	tree := map[string]interface{}{
		"attestation_report": map[string]interface{}{
			"measurement":  "deadbeef",
			"report_data":  "cf2b5bfe6f956590a7297b2d8fdd238b1a96eba3382c17ab9f5573b363dc57ad",
			"reported_tcb": map[string]interface{}{"snp": 1},
		},
		"nested": []interface{}{
			map[string]interface{}{"report-data": "aa"},
		},
	}

	path, _, ok := deepFind(tree, "report_data")
	if !ok || path != "attestation_report.report_data" {
		t.Fatalf("deepFind report_data: path=%q ok=%v", path, ok)
	}
	path, _, ok = deepFind(tree, "report-data")
	if !ok || path != "nested[0].report-data" {
		t.Fatalf("deepFind report-data: path=%q ok=%v", path, ok)
	}
	_, _, ok = deepFind(tree, "does_not_exist")
	if ok {
		t.Fatalf("unexpected find for missing key")
	}
}

func TestExtractReportDataHex(t *testing.T) {
	canonical := "cf2b5bfe6f956590a7297b2d8fdd238b1a96eba3382c17ab9f5573b363dc57ad"
	evidence := map[string]interface{}{
		"attestation_report": map[string]interface{}{
			"report_data": canonical,
		},
	}
	got, src, found := extractReportDataHex(evidence)
	if !found || got != canonical || src != "attestation_report.report_data" {
		t.Fatalf("extract: got=%q src=%q found=%v", got, src, found)
	}
}

// helpers

func toBytes(hexStr string) []byte {
	b := make([]byte, len(hexStr)/2)
	for i := 0; i < len(b); i++ {
		hi := fromHexNibble(hexStr[i*2])
		lo := fromHexNibble(hexStr[i*2+1])
		b[i] = hi<<4 | lo
	}
	return b
}

func fromHexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func asciiToInterface(s string) []interface{} {
	out := make([]interface{}, len(s))
	for i, c := range []byte(s) {
		out[i] = float64(c)
	}
	return out
}

func bytesToInterface(b []byte) []interface{} {
	out := make([]interface{}, len(b))
	for i, c := range b {
		out[i] = float64(c)
	}
	return out
}
