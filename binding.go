package main

// CE-v1 report-data binding, ported from the Enclava attestation-proxy so the
// server can reproduce the exact 64-byte SEV-SNP REPORT_DATA field the proxy
// embeds in every attestation. The browser mirrors this in web/verify.js and
// must arrive at the same bytes.
//
// Reference: attestation-proxy/src/receipts.rs (ce_v1_bytes / ce_v1_hash) and
// attestation-proxy/src/handlers.rs (tee_tls_transcript_hash / build_report_data).

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// ceV1Bytes reproduces the CE-v1 length-prefixed record encoding:
//
//	for each (label, value):
//	    u16be(len(label)) || label || u32be(len(value)) || value
func ceV1Bytes(records [][2][]byte) []byte {
	total := 0
	for _, r := range records {
		total += 2 + len(r[0]) + 4 + len(r[1])
	}
	out := make([]byte, 0, total)
	for _, r := range records {
		label, value := r[0], r[1]
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(label)))
		out = append(out, l[:]...)
		out = append(out, label...)
		var v [4]byte
		binary.BigEndian.PutUint32(v[:], uint32(len(value)))
		out = append(out, v[:]...)
		out = append(out, value...)
	}
	return out
}

// ceV1Hash is SHA-256 over ceV1Bytes(records).
func ceV1Hash(records [][2][]byte) [32]byte {
	return sha256.Sum256(ceV1Bytes(records))
}

// transcriptHash mirrors attestation-proxy tee_tls_transcript_hash:
//
//	ce_v1_hash([
//	    ("purpose", "enclava-tee-tls-v1"),
//	    ("domain", domain),
//	    ("nonce", nonce),
//	    ("leaf_spki_sha256", leafSPKI),
//	])
func transcriptHash(domain string, nonce, leafSPKI [32]byte) [32]byte {
	return ceV1Hash([][2][]byte{
		{[]byte("purpose"), []byte("enclava-tee-tls-v1")},
		{[]byte("domain"), []byte(domain)},
		{[]byte("nonce"), nonce[:]},
		{[]byte("leaf_spki_sha256"), leafSPKI[:]},
	})
}

// reportDataHex returns the 64 lowercase-hex characters that fill the SEV-SNP
// 64-byte REPORT_DATA field. The proxy stores the binding hash as ASCII hex in
// the report, so this string is the canonical comparison target.
//
//	ce_v1_hash([
//	    ("purpose", "enclava-tee-report-data-v1"),
//	    ("transcript_hash", transcriptHash(domain, nonce, leafSPKI)),
//	    ("receipt_pubkey_sha256", receiptPubkey),
//	])  -> hex
func reportDataHex(domain string, nonce, leafSPKI, receiptPubkey [32]byte) string {
	th := transcriptHash(domain, nonce, leafSPKI)
	h := ceV1Hash([][2][]byte{
		{[]byte("purpose"), []byte("enclava-tee-report-data-v1")},
		{[]byte("transcript_hash"), th[:]},
		{[]byte("receipt_pubkey_sha256"), receiptPubkey[:]},
	})
	return hex.EncodeToString(h[:])
}
