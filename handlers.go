package main

// HTTP handlers for the dashboard API.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"time"
)

type infoResponse struct {
	Runtime            runtimeFacts    `json:"runtime"`
	AttestationInfo    attestationInfo `json:"attestation_info,omitempty"`
	ProxyReachable     bool            `json:"proxy_reachable"`
	ProxyStatus        int             `json:"proxy_status,omitempty"`
	ProxyHealth        map[string]any  `json:"proxy_health,omitempty"`
	LeafSPKISha256     string          `json:"leaf_spki_sha256,omitempty"`
	LeafSPKIResolution string          `json:"leaf_spki_resolution,omitempty"`
	LeafSPKIError      string          `json:"leaf_spki_error,omitempty"`
	EvidenceContract   map[string]any  `json:"evidence_contract,omitempty"`
}

type verifyRequest struct {
	NonceB64 string `json:"nonce_b64"`
	Domain   string `json:"domain"`
}

type verifyResponse struct {
	Ok                       bool           `json:"ok"`
	NonceB64                 string         `json:"nonce_b64"`
	Domain                   string         `json:"domain"`
	AttestationType          string         `json:"attestation_type,omitempty"`
	RuntimeClass             string         `json:"runtime_class,omitempty"`
	LeafSPKISha256           string         `json:"leaf_spki_sha256,omitempty"`
	LeafSPKIResolution       string         `json:"leaf_spki_resolution,omitempty"`
	ReceiptPubkeySha256      string         `json:"receipt_pubkey_sha256,omitempty"`
	ExpectedReportDataHex    string         `json:"expected_report_data_hex"`
	EvidenceReportDataHex    string         `json:"evidence_report_data_hex"`
	EvidenceReportDataSource string         `json:"evidence_report_data_source"`
	TranscriptHashHex        string         `json:"transcript_hash_hex"`
	Match                    bool           `json:"match"`
	ProxyTimestamp           string         `json:"proxy_timestamp,omitempty"`
	Claims                   map[string]any `json:"claims,omitempty"`
	Identity                 map[string]any `json:"identity,omitempty"`
	ServerVerification       map[string]any `json:"server_verification,omitempty"`
	Policy                   map[string]any `json:"policy,omitempty"`
	Endorsements             map[string]any `json:"endorsements,omitempty"`
	Evidence                 any            `json:"evidence,omitempty"`
	DemoSecret               string         `json:"demo_secret,omitempty"`
	DemoSecretRevealed       bool           `json:"demo_secret_revealed"`
	Error                    string         `json:"error,omitempty"`
	Detail                   string         `json:"detail,omitempty"`
}

func (a *app) handleAPIInfo(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	out := infoResponse{Runtime: gatherRuntimeFacts(a.configDir, a.statePath)}

	if info, status, err := a.proxy.info(ctx); err == nil {
		out.AttestationInfo = info
		out.ProxyStatus = status
		out.ProxyReachable = status == 200
		if contract, ok := info["evidence_endpoint"]; ok {
			out.EvidenceContract = map[string]any{
				"evidence_endpoint":     contract,
				"runtime_data_contract": info["runtime_data_contract"],
				"nonce_encoding":        info["nonce_encoding"],
			}
		}
	} else {
		out.LeafSPKIError = err.Error()
	}

	if hp, status, err := a.proxy.health(ctx); err == nil && status == 200 {
		out.ProxyHealth = hp
	}

	leaf, source, err := a.resolveLeafSPKI(ctx)
	if err != nil {
		out.LeafSPKIError = stringOrDefault(out.LeafSPKIError, err.Error())
	} else {
		out.LeafSPKISha256 = leaf
		out.LeafSPKIResolution = source
	}

	writeJSON(w, http.StatusOK, out)
}

func (a *app) handleProxyInfo(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	info, status, err := a.proxy.info(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "proxy_unreachable", "detail": err.Error()})
		return
	}
	writeJSON(w, status, info)
}

func (a *app) handleAPIVerify(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	var req verifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, verifyResponse{Error: "bad_request", Detail: err.Error()})
		return
	}
	req.NonceB64 = strings.TrimSpace(req.NonceB64)
	req.Domain = strings.TrimSpace(strings.ToLower(req.Domain))
	if req.NonceB64 == "" || req.Domain == "" {
		writeJSON(w, http.StatusBadRequest, verifyResponse{Error: "missing_parameter", Detail: "nonce_b64 and domain are required"})
		return
	}
	requestDomain := requestHostname(r.Host)
	if requestDomain == "" || req.Domain != requestDomain {
		writeJSON(w, http.StatusBadRequest, verifyResponse{
			Error:  "domain_mismatch",
			Detail: "domain must match the HTTPS request hostname",
		})
		return
	}
	nonce, err := decodeNonce(req.NonceB64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, verifyResponse{Error: "nonce_invalid", Detail: err.Error(), NonceB64: req.NonceB64})
		return
	}

	leafHex, source, err := a.resolveLeafSPKI(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, verifyResponse{Error: "leaf_spki_unavailable", Detail: err.Error()})
		return
	}

	ar, _, ae, err := a.proxy.attest(ctx, req.NonceB64, req.Domain, leafHex)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, verifyResponse{Error: "attestation_proxy_error", Detail: err.Error()})
		return
	}
	if ae != nil {
		writeJSON(w, http.StatusBadGateway, verifyResponse{Error: ae.Error, Detail: ae.Detail})
		return
	}

	resp := buildVerifyResponse(a.configDir, req, nonce, leafHex, source, ar)
	writeJSON(w, http.StatusOK, resp)
}

func requestHostname(hostport string) string {
	hostport = strings.TrimSpace(strings.ToLower(hostport))
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(hostport, "[]")
}

// resolveLeafSPKI returns (hex, source, err) where source is "env" or "tls-dial".
func (a *app) resolveLeafSPKI(ctx context.Context) (string, string, error) {
	if v := strings.TrimSpace(a.proxy.tlsSPKIOverride); v != "" {
		return strings.ToLower(v), "env", nil
	}
	h, err := a.proxy.resolveLeafSPKISha256Hex(ctx)
	if err != nil {
		return "", "", err
	}
	return h, "tls-dial", nil
}

// buildVerifyResponse turns an attestation-proxy response into the verify
// payload, computing the expected REPORT_DATA independently of the proxy.
func buildVerifyResponse(configDir string, req verifyRequest, nonce [32]byte, leafHex, leafSource string, ar *attestationResponse) verifyResponse {
	resp := verifyResponse{
		NonceB64:            req.NonceB64,
		Domain:              req.Domain,
		AttestationType:     ar.AttestationType,
		RuntimeClass:        ar.RuntimeClass,
		LeafSPKISha256:      leafHex,
		LeafSPKIResolution:  leafSource,
		ReceiptPubkeySha256: ar.RuntimeDataBinding.ReceiptPubkeySha256,
		ProxyTimestamp:      ar.Timestamp,
		Claims:              ar.Claims,
		Identity:            ar.Identity,
		ServerVerification:  ar.ServerVerification,
		Policy:              ar.Policy,
		Endorsements:        ar.Endorsements,
		Evidence:            ar.Evidence.JSON,
	}

	leaf, err := decodeHex32(leafHex)
	if err == nil {
		receipt, err2 := decodeHex32(ar.RuntimeDataBinding.ReceiptPubkeySha256)
		if err2 == nil {
			th := transcriptHash(req.Domain, nonce, leaf)
			resp.TranscriptHashHex = hex.EncodeToString(th[:])
			resp.ExpectedReportDataHex = reportDataHex(req.Domain, nonce, leaf, receipt)
		} else {
			resp.Error = "receipt_pubkey_unparseable"
			resp.Detail = err2.Error()
		}
	} else {
		resp.Error = "leaf_spki_unparseable"
		resp.Detail = err.Error()
	}

	evidenceHex, src, found := extractReportDataHex(ar.Evidence.JSON)
	resp.EvidenceReportDataHex = evidenceHex
	resp.EvidenceReportDataSource = src
	if found && resp.ExpectedReportDataHex != "" {
		resp.Match = strings.EqualFold(resp.ExpectedReportDataHex, evidenceHex)
	}

	resp.Ok = resp.Match && resp.Error == ""

	// Reveal the demo secret only after the binding proof passes. The secret was
	// delivered to the TEE at startup; showing it here is a demo affordance for a
	// viewer who has cryptographically confirmed a live, bound attestation.
	if resp.Ok {
		if secret, ok := readConfigValueOk(configDir, "DEMO_SECRET"); ok && secret != "" {
			resp.DemoSecret = strings.TrimRight(secret, "\r\n")
			resp.DemoSecretRevealed = true
		}
	}
	return resp
}

func decodeNonce(b64 string) ([32]byte, error) {
	var out [32]byte
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// tolerate URL-safe variants
		raw, err = base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			return out, err
		}
	}
	if len(raw) != 32 {
		return out, errNonceLen(len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

func decodeHex32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, errLen(32, len(b))
	}
	copy(out[:], b)
	return out, nil
}

func stringOrDefault(def, alt string) string {
	if def != "" {
		return def
	}
	return alt
}
