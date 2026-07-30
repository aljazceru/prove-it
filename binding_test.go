package main

import (
	"encoding/hex"
	"testing"
)

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestCeV1Bytes_Encoding locks the length-prefixed record layout against the
// attestation-proxy reference. Any drift here breaks binding verification.
func TestCeV1Bytes_Encoding(t *testing.T) {
	got := ceV1Bytes([][2][]byte{{[]byte("a"), []byte("b")}})
	want := []byte{0x00, 0x01, 0x61, 0x00, 0x00, 0x00, 0x01, 0x62}
	if !equalBytes(got, want) {
		t.Fatalf("ceV1Bytes(a,b) = %x, want %x", got, want)
	}

	// Empty value still writes the u32 length prefix.
	got = ceV1Bytes([][2][]byte{{[]byte("purpose"), nil}})
	want = []byte{0x00, 0x07, 'p', 'u', 'r', 'p', 'o', 's', 'e', 0x00, 0x00, 0x00, 0x00}
	if !equalBytes(got, want) {
		t.Fatalf("ceV1Bytes(purpose,empty) = %x, want %x", got, want)
	}

	// Records are concatenated in order.
	got = ceV1Bytes([][2][]byte{{[]byte("a"), []byte("1")}, {[]byte("b"), []byte("2")}})
	// a: 00 01 61 | 00 00 00 01 31   b: 00 01 62 | 00 00 00 01 32
	want = []byte{0x00, 0x01, 0x61, 0x00, 0x00, 0x00, 0x01, 0x31,
		0x00, 0x01, 0x62, 0x00, 0x00, 0x00, 0x01, 0x32}
	if !equalBytes(got, want) {
		t.Fatalf("ceV1Bytes(multi) = %x, want %x", got, want)
	}
}

// TestCeV1Hash_Golden pins SHA-256 over the canonical encoding, computed with
// the independent python reference in /tmp/cev1_ref.py.
func TestCeV1Hash_Golden(t *testing.T) {
	h := ceV1Hash([][2][]byte{{[]byte("a"), []byte("b")}})
	want := "065e0731c1e2f83b4252255606116c07fbdda093fdab6ce907f9e23f42b0d9f2"
	if got := hex.EncodeToString(h[:]); got != want {
		t.Fatalf("ceV1Hash(a,b) = %s, want %s", got, want)
	}
}

// TestReportDataHex_Golden pins the full REPORT_DATA derivation against the
// python reference vector. The browser (web/verify.js) is pinned to the same.
func TestReportDataHex_Golden(t *testing.T) {
	domain := "prove-it.app.preprod.enclava.dev"

	var nonce [32]byte
	for i := 0; i < 32; i++ {
		nonce[i] = byte(i)
	}
	leaf, _ := decodeHex32("01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da")
	receipt, _ := decodeHex32("05080b0e1114171a1d202326292c2f3235383b3e4144474a4d505356595c5f62")

	th := transcriptHash(domain, nonce, leaf)
	if got := hex.EncodeToString(th[:]); got !=
		"63ed321b8e8066dbaa267e3285ae1a42e60a541cf4857b74e793e31f59aeb822" {
		t.Fatalf("transcriptHash mismatch: %s", got)
	}

	got := reportDataHex(domain, nonce, leaf, receipt)
	want := "cf2b5bfe6f956590a7297b2d8fdd238b1a96eba3382c17ab9f5573b363dc57ad"
	if got != want {
		t.Fatalf("reportDataHex = %s, want %s", got, want)
	}
}

func TestReportDataHex_Properties(t *testing.T) {
	var nonce [32]byte
	var leaf [32]byte
	var receipt [32]byte
	rd := reportDataHex("x.example", nonce, leaf, receipt)
	if len(rd) != 64 {
		t.Fatalf("report_data_hex len = %d, want 64", len(rd))
	}
	for _, r := range rd {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Fatalf("report_data_hex not lowercase hex: %s", rd)
		}
	}
	// Changing the nonce must change the report data.
	nonce[0] = 1
	rd2 := reportDataHex("x.example", nonce, leaf, receipt)
	if rd == rd2 {
		t.Fatalf("report_data_hex unchanged after nonce change")
	}
}
