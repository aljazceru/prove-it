// web/verify.js
// CE-v1 report-data binding, mirroring prove-it/binding.go and the Enclava
// attestation-proxy. The browser independently recomputes the SEV-SNP
// REPORT_DATA field and checks it against (a) the server's claimed value and
// (b) the value embedded in the hardware attestation report. If all three
// agree, the attestation is provably live and bound to this browser session.

export function hexToBytes(hex) {
  hex = String(hex).toLowerCase().replace(/[^0-9a-f]/g, "");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

export function bytesToHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function base64ToBytes(b64) {
  b64 = String(b64).replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// CE-v1 records: u16be(len(label)) || label || u32be(len(value)) || value
function ceV1Bytes(records) {
  let total = 0;
  for (const [label, value] of records) total += 2 + label.length + 4 + value.length;
  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  let off = 0;
  for (const [label, value] of records) {
    dv.setUint16(off, label.length);
    off += 2;
    out.set(label, off);
    off += label.length;
    dv.setUint32(off, value.length);
    off += 4;
    out.set(value, off);
    off += value.length;
  }
  return out;
}

async function sha256(bytes) {
  const h = await crypto.subtle.digest("SHA-256", bytes);
  return new Uint8Array(h);
}

async function ceV1Hash(records) {
  return sha256(ceV1Bytes(records));
}

const enc = new TextEncoder();

function rec(label, value) {
  return [enc.encode(label), value];
}

export async function transcriptHash(domain, nonce, leafSpki) {
  return ceV1Hash([
    rec("purpose", enc.encode("enclava-tee-tls-v1")),
    rec("domain", enc.encode(domain)),
    rec("nonce", nonce),
    rec("leaf_spki_sha256", leafSpki),
  ]);
}

export async function reportDataHex(domain, nonce, leafSpki, receipt) {
  const th = await transcriptHash(domain, nonce, leafSpki);
  const h = await ceV1Hash([
    rec("purpose", enc.encode("enclava-tee-report-data-v1")),
    rec("transcript_hash", th),
    rec("receipt_pubkey_sha256", receipt),
  ]);
  return bytesToHex(h);
}

export function randomNonceBytes(n = 32) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

// Golden vector shared with binding_test.go. Used only by the self-test that
// runs on page load to confirm the browser crypto matches the server.
export const GOLDEN = {
  domain: "prove-it.app.preprod.enclava.dev",
  nonce: new Uint8Array(Array.from({ length: 32 }, (_, i) => i)),
  leafSpki: hexToBytes(
    "01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da"
  ),
  receipt: hexToBytes(
    "05080b0e1114171a1d202326292c2f3235383b3e4144474a4d505356595c5f62"
  ),
  transcriptHash: "63ed321b8e8066dbaa267e3285ae1a42e60a541cf4857b74e793e31f59aeb822",
  reportData: "cf2b5bfe6f956590a7297b2d8fdd238b1a96eba3382c17ab9f5573b363dc57ad",
};
