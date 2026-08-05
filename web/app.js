// web/app.js — prove-it dashboard logic. Drives /api/info and /api/verify and
// renders the verification. The cryptographic re-derivation happens in
// verify.js, in the browser, independent of the server.

import {
  reportDataHex,
  transcriptHash,
  bytesToHex,
  bytesToBase64,
  hexToBytes,
  randomNonceBytes,
  GOLDEN,
} from "./verify.js";

const el = (id) => document.getElementById(id);
let lastInfo = null;

function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])
  );
}
function short(s, n = 16) {
  s = String(s ?? "");
  return s.length > n * 2 ? `${s.slice(0, n)}…${s.slice(-6)}` : s;
}
function fmtHash(s) {
  return `<span class="mono" title="${esc(s)}">${esc(short(s, 20))}</span>`;
}

// ----- status banner ---------------------------------------------------------
function setStatus(state, title, detail) {
  const banner = el("status");
  banner.className = `banner ${state}`;
  el("status-ico").textContent =
    state === "attested" ? "✅" :
    state === "simulated" ? "🧪" :
    state === "warn" || state === "not-tee" ? "⚠️" :
    state === "failed" || state === "err" ? "❌" : "○";
  el("status-title").textContent = title;
  el("status-detail").textContent = detail;
}

function resetProofChain() {
  document.querySelectorAll("[data-proof-step]").forEach((node) => {
    node.classList.remove("passed", "failed");
  });
}

function markProofStep(number, state = "passed") {
  const node = document.querySelector(`[data-proof-step="${number}"]`);
  if (node) node.classList.add(state);
}

// ----- badges ----------------------------------------------------------------
function renderBadges(info) {
  const rt = info.runtime || {};
  const parts = [];
  parts.push(`<span class="badge">${esc(rt.version || "prove-it")}</span>`);
  const ai = info.attestation_info || {};
  if (ai.attestation_type) parts.push(`<span class="badge">${esc(ai.attestation_type)}</span>`);
  if (ai.runtime_class) parts.push(`<span class="badge">${esc(ai.runtime_class)}</span>`);
  if (info.proxy_reachable) parts.push(`<span class="badge ok">attestation-proxy ●</span>`);
  else parts.push(`<span class="badge warn">attestation-proxy ○</span>`);
  el("header-badges").innerHTML = parts.join("");
}

// ----- runtime facts ---------------------------------------------------------
function renderFacts(info) {
  const rt = info.runtime || {};
  const id = info.identity || {};
  el("instance-label").textContent = rt.instance_label || "prove-it";

  const kv = (rows) =>
    rows
      .map(
        ([k, v]) =>
          `<dt>${esc(k)}</dt><dd>${v === null || v === undefined || v === "" ? '<span class="dim">—</span>' : v}</dd>`
      )
      .join("");

  const teeIndicators = (rt.tee_indicators || []);
  const teePills = teeIndicators.length
    ? teeIndicators.map((t) => `<span class="pill on">${esc(t)}</span>`).join(" ")
    : `<span class="pill">none detected</span>`;

  el("facts").innerHTML = [
    `<div class="card">
       <h3>Confidential runtime</h3>
       <dl class="kv">${kv([
         ["TEE", teePills],
         ["config-ready", rt.config_ready ? '<span class="badge ok">yes</span>' : '<span class="badge">no</span>'],
         ["config keys", (rt.config_keys || []).map((k) => `<span class="pill">${esc(k)}</span>`).join(" ") || '<span class="dim">none</span>'],
         ["state volume", rt.state_writable ? `<span class="badge ok">writable ${esc(rt.state_path)}</span>` : '<span class="badge warn">not writable</span>'],
       ])}</dl>
     </div>`,
    `<div class="card">
       <h3>Attested identity</h3>
       <dl class="kv">${kv([
         ["image ref", fmtHash((id.attested && id.attested.image_reference) || "")],
         ["image digest", fmtHash((id.attested && id.attested.image_digest) || "")],
         ["namespace", esc((id.attested && id.attested.namespace) || "")],
         ["service account", esc((id.attested && id.attested.service_account) || "")],
         ["init_data hash", fmtHash((id.attested && id.attested.init_data_hash) || "")],
       ])}</dl>
     </div>`,
    `<div class="card">
       <h3>TEE TLS binding</h3>
       <dl class="kv">${kv([
         ["leaf SPKI sha256", fmtHash(info.leaf_spki_sha256)],
         ["resolution", esc(info.leaf_spki_resolution || "") + (info.leaf_spki_error ? ` <span class="dim">(${esc(info.leaf_spki_error)})</span>` : "")],
         ["evidence", (info.evidence_contract && info.evidence_contract.evidence_endpoint) ? `<span class="mono">${esc(info.evidence_contract.evidence_endpoint)}</span>` : '<span class="dim">—</span>'],
       ])}</dl>
     </div>`,
    `<div class="card">
       <h3>Secret delivery</h3>
       <dl class="kv">${kv([
         ["demo secret", rt.demo_secret_present ? '<span class="badge ok">present in TEE</span>' : '<span class="badge warn">absent</span>'],
         ["sha256", fmtHash(rt.demo_secret_sha256)],
         ["hostname", esc(rt.hostname)],
       ])}</dl>
       <div class="dim fact-note">Secrets arrive through the confidential config handoff; their plaintext exists only in hardware-encrypted memory.</div>
     </div>`,
  ].join("");
}

// ----- load info -------------------------------------------------------------
async function loadInfo() {
  try {
    const r = await fetch("/api/info", { cache: "no-store" });
    const info = await r.json();
    lastInfo = info;
    renderBadges(info);
    renderFacts(info);
    if (!info.proxy_reachable) {
      setStatus("not-tee", "Not in a confidential VM",
        "The attestation-proxy is unreachable. This image is running outside an AMD SEV-SNP confidential workload, so no hardware attestation is available. Deploy it on Enclava to see a verified state.");
    } else if (info.leaf_spki_error) {
      setStatus("warn", "Attestation surface partially available",
        `Proxy reachable but the TEE TLS SPKI could not be resolved: ${info.leaf_spki_error}`);
    } else {
      setStatus("warn", "Binding surface ready — verify now",
        "The attestation-proxy is live. Run verification to check freshness and REPORT_DATA binding; hardware trust still requires independent signature and TCB appraisal.");
    }
    renderSecret({ demo_secret_present: info.runtime.demo_secret_present, demo_secret_sha256: info.runtime.demo_secret_sha256, demo_secret_revealed: false });
  } catch (e) {
    setStatus("err", "Could not initialize prove-it", String(e));
  }
}

// ----- verify steps ----------------------------------------------------------
function addStep(label) {
  const li = document.createElement("li");
  const mark = document.createElement("div");
  mark.className = "mark wait";
  mark.textContent = "…";
  const body = document.createElement("div");
  body.className = "body";
  const t = document.createElement("div");
  t.className = "t";
  t.textContent = label;
  const d = document.createElement("div");
  d.className = "d";
  body.append(t, d);
  li.append(mark, body);
  el("verify-steps").append(li);
  return {
    ok(detail) { mark.className = "mark ok"; mark.textContent = "✓"; if (detail) d.textContent = detail; },
    err(detail) { mark.className = "mark err"; mark.textContent = "✗"; if (detail) d.textContent = detail; },
    set(detail) { d.textContent = detail; },
  };
}

function compareRow(label, value, match) {
  const cls = value ? (match ? "match" : "differ") : "";
  return `<div class="row"><div class="lbl">${esc(label)}</div><div class="val ${cls}">${value ? esc(value) : '<span class="dim">(missing)</span>'}</div></div>`;
}

function renderSecret(data) {
  const wrap = el("secret-wrap");
  const present = data.demo_secret_present ?? (lastInfo && lastInfo.runtime && lastInfo.runtime.demo_secret_present);
  if (!present) { wrap.innerHTML = ""; return; }
  if (data.demo_secret_revealed) {
    wrap.innerHTML = `<div class="secret">
      <span class="lock">🔓</span>
      <div><strong>Secret revealed</strong>
        <div class="dim">Delivered to the TEE at startup via the confidential config handoff. Shown only after the browser confirmed the fresh REPORT_DATA binding.</div>
      </div>
      <code class="revealed">${esc(data.demo_secret)}</code>
    </div>`;
  } else {
    const sha = (lastInfo && lastInfo.runtime && lastInfo.runtime.demo_secret_sha256) || data.demo_secret_sha256 || "";
    wrap.innerHTML = `<div class="secret locked">
      <span class="lock">🔒</span>
      <div><strong>Secret locked</strong>
        <div class="dim">sha256: ${esc(sha)} — pass live verification to reveal.</div>
      </div>
    </div>`;
  }
}

async function downloadProofBundle() {
  const button = el("download-proof-btn");
  const note = el("download-proof-note");
  button.disabled = true;
  note.textContent = "Fetching fresh platform evidence…";
  try {
    const nonce = randomNonceBytes(32);
    const nonceB64url = bytesToBase64(nonce)
      .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    const response = await fetch(`/.well-known/confidential/proof-bundle?nonce=${nonceB64url}`, {
      headers: { accept: "application/vnd.enclava.proof-bundle.v1" },
      cache: "no-store",
      credentials: "omit",
    });
    if (!response.ok || response.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/vnd.enclava.proof-bundle.v1") {
      throw new Error(`proof endpoint returned HTTP ${response.status}`);
    }
    const bytes = await response.arrayBuffer();
    if (bytes.byteLength > 1048576) throw new Error("proof bundle exceeds the v1 limit");
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([bytes], { type: "application/vnd.enclava.proof-bundle.v1" }));
    link.download = `prove-it-proof-${Date.now()}.ce`;
    link.click();
    URL.revokeObjectURL(link.href);
    note.textContent = "Raw platform evidence downloaded; choose policy independently.";
  } catch (error) {
    note.textContent = `Could not download proof: ${error.message}`;
  } finally {
    button.disabled = false;
  }
}

// ----- run live verification -------------------------------------------------
async function runVerify() {
  const btn = el("verify-btn");
  btn.disabled = true;
  el("verify-note").textContent = "";
  const steps = el("verify-steps");
  steps.hidden = false;
  steps.innerHTML = "";
  el("compare").hidden = true;
  resetProofChain();

  const nonce = randomNonceBytes(32);
  const nonceB64 = bytesToBase64(nonce);
  const domain = location.hostname || "localhost";

  const s1 = addStep("Generate a fresh 32-byte nonce in the browser");
  s1.ok(`nonce=${short(bytesToHex(nonce), 16)} (${nonce.length} bytes via crypto.getRandomValues) — never sent anywhere except this request`);
  markProofStep(1);

  const s2 = addStep("Request fresh evidence bound to this nonce");
  try {
    const r = await fetch("/api/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ nonce_b64: nonceB64, domain }),
    });
    const data = await r.json();
    el("evidence-pre").textContent = JSON.stringify(data, null, 2);

    if (!r.ok || data.error) {
      s2.err(`${data.error || ("http " + r.status)}: ${data.detail || ""}`.trim());
      markProofStep(2, "failed");
      setStatus("err", "Verification failed", data.error ? `attestation-proxy: ${data.detail || data.error}` : `unexpected response (HTTP ${r.status})`);
      btn.disabled = false;
      return;
    }
    s2.ok(`${data.attestation_type || "attestation"} · ${data.runtime_class || ""} · proxy ${data.proxy_timestamp || ""}`);
    markProofStep(2);

    const s3 = addStep("Extract REPORT_DATA from the returned evidence");
    if (data.evidence_report_data_hex) {
      s3.ok(`source=${data.evidence_report_data_source} → ${short(data.evidence_report_data_hex, 20)}`);
      markProofStep(3);
    } else {
      s3.err(`REPORT_DATA not located in evidence JSON (${data.evidence_report_data_source || "none"}) — cannot complete binding`);
      markProofStep(3, "failed");
    }

    const s4 = addStep("Independently re-derive the binding in the browser");
    let browserRd = "";
    try {
      browserRd = await reportDataHex(domain, nonce, hexToBytes(data.leaf_spki_sha256), hexToBytes(data.receipt_pubkey_sha256));
    } catch (e) {
      s4.err("browser crypto failed: " + e);
      setStatus("err", "Browser crypto failed", String(e));
      btn.disabled = false;
      return;
    }
    const browserEqServer = browserRd === data.expected_report_data_hex;
    const browserDetail = browserEqServer
      ? `browser=${short(browserRd, 20)}  matches server expected`
      : `browser=${short(browserRd, 20)}  server=${short(data.expected_report_data_hex, 20)}  (mismatch!)`;
    (browserEqServer ? s4.ok : s4.err)(browserDetail);
    markProofStep(4, browserEqServer ? "passed" : "failed");

    const s5 = addStep("Confirm three-way match: browser == server == evidence");
    const hwEq = !!data.evidence_report_data_hex && browserRd === data.evidence_report_data_hex;
    const allMatch = browserEqServer && hwEq;
    const matchDetail = allMatch
      ? "✓ browser == server-expected == evidence REPORT_DATA"
      : (hwEq ? "browser==evidence but server differs" : "evidence REPORT_DATA differs from recompute — binding NOT proven");
    (allMatch ? s5.ok : s5.err)(matchDetail);
    markProofStep(5, allMatch ? "passed" : "failed");

    el("compare").hidden = false;
    el("compare").innerHTML =
      compareRow("browser", browserRd, allMatch) +
      compareRow("server expected", data.expected_report_data_hex, browserEqServer) +
      compareRow("evidence REPORT_DATA", data.evidence_report_data_hex, hwEq);

    renderSecret(data);
    if (allMatch) {
      setStatus("attested", "Fresh binding verified",
        `The evidence REPORT_DATA matches this browser's nonce, ${domain}, and the in-TEE proxy key. This is not yet an AMD signature or TCB appraisal.`);
    } else {
      setStatus("failed", "Binding not verified",
        "The recomputed binding did not match the evidence REPORT_DATA. Do not trust this response.");
    }
  } catch (e) {
    s2.err(String(e));
    setStatus("err", "Could not complete attestation", String(e));
  } finally {
    btn.disabled = false;
  }
}

// ----- browser self-test -----------------------------------------------------
async function runSelfTest() {
  const note = el("verify-note");
  note.textContent = "running self-test…";
  try {
    const th = await transcriptHash(GOLDEN.domain, GOLDEN.nonce, GOLDEN.leafSpki);
    const thHex = bytesToHex(th);
    const rd = await reportDataHex(GOLDEN.domain, GOLDEN.nonce, GOLDEN.leafSpki, GOLDEN.receipt);
    if (thHex === GOLDEN.transcriptHash && rd === GOLDEN.reportData) {
      note.innerHTML = `<span class="badge ok">self-test PASS</span> browser CE-v1 matches golden vector (${short(rd, 12)}).`;
    } else {
      note.innerHTML = `<span class="badge err">self-test FAIL</span> th=${short(thHex, 12)} rd=${short(rd, 12)}`;
    }
  } catch (e) {
    note.innerHTML = `<span class="badge err">self-test ERROR</span> ${esc(e)}`;
  }
}

// ----- demo fixture (?demo=1) ------------------------------------------------
async function loadDemoFixture() {
  const rt = {
    version: "0.2.1",
    instance_label: "demo-fixture",
    config_ready: true,
    config_keys: ["INSTANCE_LABEL", "DEMO_SECRET"],
    state_writable: true,
    state_path: "/state/app-data",
    tee_indicators: ["fixture:simulated"],
    hostname: "demo.local",
    demo_secret_present: true,
    demo_secret_sha256: "bb2b2b…(fixture)",
  };
  lastInfo = {
    runtime: rt,
    attestation_info: { attestation_type: "coco-sev-snp (simulated)", runtime_class: "kata-qemu-snp (simulated)" },
    proxy_reachable: true,
    leaf_spki_sha256: bytesToHex(GOLDEN.leafSpki),
    leaf_spki_resolution: "fixture",
    evidence_contract: { evidence_endpoint: "/v1/attestation?nonce=…&domain=…&leaf_spki_sha256=… (fixture)" },
  };
  renderBadges(lastInfo);
  renderFacts(lastInfo);
  renderSecret({ demo_secret_present: true, demo_secret_sha256: rt.demo_secret_sha256, demo_secret_revealed: false });
  setStatus("simulated", "DEMO FIXTURE — simulated values, not a live attestation",
    "The prove-it API is unavailable, so this view uses canned values. Deploy on Enclava for fresh binding evidence and use an independent appraiser for hardware trust.");

  // Render a self-consistent (but simulated) verification using the golden vector.
  const steps = el("verify-steps");
  steps.hidden = false;
  steps.innerHTML = "";
  const mk = (t, d, ok) => `<li><div class="mark ${ok ? "ok" : "err"}">${ok ? "✓" : "✗"}</div><div class="body"><div class="t">${esc(t)}</div><div class="d">${esc(d)}</div></div></li>`;
  steps.innerHTML =
    mk("Generate nonce (fixture)", "nonce=fixed golden vector (simulated)", true) +
    mk("Request attestation (fixture)", "no hardware present — fixture response", false);
  el("compare").hidden = false;
  el("compare").innerHTML =
    compareRow("browser", GOLDEN.reportData, true) +
    compareRow("server expected", GOLDEN.reportData, true) +
    compareRow("evidence REPORT_DATA", GOLDEN.reportData + " (simulated)", true);
}

// ----- wire up ---------------------------------------------------------------
el("verify-btn").addEventListener("click", runVerify);
el("selftest-btn").addEventListener("click", runSelfTest);
el("download-proof-btn").addEventListener("click", downloadProofBundle);

const params = new URLSearchParams(location.search);
if (params.get("demo") === "1") {
  loadDemoFixture();
} else {
  loadInfo();
  // Run the browser self-test once on load to prove the on-page crypto is sound.
  runSelfTest();
}
