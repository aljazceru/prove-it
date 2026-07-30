package main

// Attestation-proxy client. prove-it runs alongside attestation-proxy in the
// same confidential pod (HTTP on 127.0.0.1:8081, self-signed TLS on :8443).
// It mediates the proxy's /v1/attestation flow so the browser can drive a live
// attestation without needing direct access to the in-pod attestation surface.
//
// Reference: attestation-proxy/src/{config.rs,handlers.rs}.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultProxyHTTPURL = "http://127.0.0.1:8081"
	defaultProxyTLSURL  = "https://127.0.0.1:8443"
)

type attestationProxyClient struct {
	httpURL         string
	tlsURL          string
	tlsSPKIOverride string // hex; env ATTESTATION_PROXY_TLS_SPKI_SHA256
	http            *http.Client
}

func newAttestationProxyClient() *attestationProxyClient {
	return &attestationProxyClient{
		httpURL:         envOr("ATTESTATION_PROXY_URL", defaultProxyHTTPURL),
		tlsURL:          envOr("ATTESTATION_PROXY_TLS_URL", defaultProxyTLSURL),
		tlsSPKIOverride: strings.TrimSpace(envOr("ATTESTATION_PROXY_TLS_SPKI_SHA256", "")),
		http: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// attestationInfo is the /v1/attestation/info payload, passed through to the UI.
type attestationInfo map[string]interface{}

func (c *attestationProxyClient) info(ctx context.Context) (attestationInfo, int, error) {
	return c.getJSON(ctx, c.httpURL+"/v1/attestation/info")
}

func (c *attestationProxyClient) health(ctx context.Context) (map[string]interface{}, int, error) {
	return c.getJSON(ctx, c.httpURL+"/health")
}

// attestationResponse mirrors the fields of the proxy /v1/attestation success
// body that prove-it consumes. Everything else is forwarded as raw JSON.
type attestationResponse struct {
	Version            string `json:"version"`
	Timestamp          string `json:"timestamp"`
	AttestationType    string `json:"attestation_type"`
	RuntimeClass       string `json:"runtime_class"`
	Nonce              string `json:"nonce"`
	RuntimeDataBinding struct {
		Scheme              string `json:"scheme"`
		Domain              string `json:"domain"`
		LeafSPKISha256      string `json:"leaf_spki_sha256"`
		ReceiptPubkeySha256 string `json:"receipt_pubkey_sha256"`
	} `json:"runtime_data_binding"`
	Evidence struct {
		Format      string      `json:"format"`
		PayloadB64  string      `json:"payload_b64"`
		JSON        interface{} `json:"json"`
		ContentType string      `json:"content_type"`
	} `json:"evidence"`
	Claims             map[string]interface{} `json:"claims"`
	ClaimsMeta         map[string]interface{} `json:"claims_meta"`
	Identity           map[string]interface{} `json:"identity"`
	ServerVerification map[string]interface{} `json:"server_verification"`
	Policy             map[string]interface{} `json:"policy"`
	Endorsements       map[string]interface{} `json:"endorsements"`
}

// attestationError is the shape the proxy returns on failure.
type attestationError struct {
	Error     string `json:"error"`
	Detail    string `json:"detail"`
	Expected  string `json:"expected"` // for leaf_spki_sha256_mismatch
	Timestamp string `json:"timestamp"`
}

func (c *attestationProxyClient) attest(
	ctx context.Context,
	nonceB64, domain, leafSPKISha256Hex string,
) (*attestationResponse, int, *attestationError, error) {
	q := url.Values{}
	q.Set("nonce", nonceB64)
	q.Set("domain", domain)
	q.Set("leaf_spki_sha256", leafSPKISha256Hex)
	endpoint := c.httpURL + "/v1/attestation?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, &attestationError{
			Error:  "attestation_proxy_unreachable",
			Detail: err.Error(),
		}, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		var ae attestationError
		_ = json.Unmarshal(body, &ae)
		if ae.Error == "" {
			ae.Error = fmt.Sprintf("attestation_proxy_status_%d", resp.StatusCode)
			ae.Detail = string(body)
		}
		return nil, resp.StatusCode, &ae, nil
	}

	var ar attestationResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return nil, resp.StatusCode, &attestationError{
			Error:  "attestation_proxy_bad_json",
			Detail: err.Error(),
		}, nil
	}
	return &ar, resp.StatusCode, nil, nil
}

// resolveLeafSPKISha256Hex returns the attestation-proxy's TLS leaf
// SubjectPublicKeyInfo SHA-256, hex-encoded. The proxy requires the caller to
// supply this value and rejects mismatches, so prove-it resolves it from:
//  1. env ATTESTATION_PROXY_TLS_SPKI_SHA256 (preferred; platform-injected), or
//  2. a live TLS handshake against the proxy's :8443 listener, computing the
//     SPKI hash from the self-signed leaf certificate.
func (c *attestationProxyClient) resolveLeafSPKISha256Hex(ctx context.Context) (string, error) {
	if v := strings.TrimSpace(c.tlsSPKIOverride); v != "" {
		return strings.ToLower(v), nil
	}
	u, err := url.Parse(c.tlsURL)
	if err != nil {
		return "", fmt.Errorf("parse tls url: %w", err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "8443"
	}
	addr := net.JoinHostPort(host, port)

	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: true, // self-signed, in-TEE; we only need the leaf SPKI.
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("dial attestation-proxy tls %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	peer := conn.(*tls.Conn)
	state := peer.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("attestation-proxy presented no leaf certificate")
	}
	leaf := state.PeerCertificates[0]
	spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal leaf spki: %w", err)
	}
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:]), nil
}

func (c *attestationProxyClient) getJSON(ctx context.Context, endpoint string) (map[string]interface{}, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]interface{}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &out) // best-effort; status matters more than body
	}
	return out, resp.StatusCode, nil
}

// ----------------------------------------------------------------------------
// REPORT_DATA extraction from the CoCo attestation report (evidence.json)
// ----------------------------------------------------------------------------

// extractReportDataHex searches the evidence JSON for the SEV-SNP REPORT_DATA
// field and normalizes it to the canonical 64-char lowercase hex string of the
// 32-byte binding hash. Different CoCo report renderings encode the field as:
//   - a 64-char hex string (already canonical),
//   - a 128-char hex string (the 64 raw bytes hex-encoded),
//   - base64 of 64 bytes (raw) or 32 bytes (the hash directly), or
//   - an array of integers.
//
// Returns (hex, sourcePath, found).
func extractReportDataHex(evidence interface{}) (string, string, bool) {
	path, v, ok := deepFind(evidence, "report_data")
	if !ok {
		// Some renderings use a hyphen.
		path, v, ok = deepFind(evidence, "report-data")
	}
	if !ok {
		return "", "", false
	}
	hexStr, ok := normalizeReportData(v)
	if !ok {
		return "", path + "(unparseable)", false
	}
	return hexStr, path, true
}

// deepFind does a breadth-limited case-insensitive search for key in nested
// map/slice structures and returns the path (e.g. "attestation_report.report_data").
func deepFind(node interface{}, key string) (string, interface{}, bool) {
	target := strings.ToLower(key)
	type frame struct {
		node  interface{}
		path  string
		depth int
	}
	q := []frame{{node, "", 0}}
	for len(q) > 0 {
		cur := q[0]
		q = q[1:]
		if cur.depth > 4 {
			continue
		}
		switch v := cur.node.(type) {
		case map[string]interface{}:
			for k, val := range v {
				p := k
				if cur.path != "" {
					p = cur.path + "." + k
				}
				if strings.ToLower(k) == target {
					return p, val, true
				}
				q = append(q, frame{val, p, cur.depth + 1})
			}
		case []interface{}:
			for i, val := range v {
				p := fmt.Sprintf("%s[%d]", cur.path, i)
				q = append(q, frame{val, p, cur.depth + 1})
			}
		}
	}
	return "", nil, false
}

// normalizeReportData reduces any of the supported encodings to the canonical
// 64-char lowercase hex of the 32-byte binding hash.
func normalizeReportData(v interface{}) (string, bool) {
	switch val := v.(type) {
	case string:
		s := strings.TrimSpace(strings.ToLower(val))
		// 64 hex chars -> canonical already.
		if len(s) == 64 && isHex(s) {
			return s, true
		}
		// 128 hex chars -> the 64 raw bytes hex-encoded; those bytes are ASCII hex.
		if len(s) == 128 && isHex(s) {
			raw, err := hex.DecodeString(s)
			if err == nil && len(raw) == 64 && isASCIIDigitOrLowerHex(raw) {
				return string(raw), true
			}
		}
		// base64 of 64 raw bytes.
		if b, err := base64.StdEncoding.DecodeString(val); err == nil && len(b) == 64 && isASCIIDigitOrLowerHex(b) {
			return string(b), true
		}
		// base64 of 32 bytes -> the hash directly.
		if b, err := base64.StdEncoding.DecodeString(val); err == nil && len(b) == 32 {
			return hex.EncodeToString(b), true
		}
		// Raw 64 ASCII hex chars that got split as a string of bytes already handled above.
		return "", false
	case []interface{}:
		b := make([]byte, 0, len(val))
		for _, n := range val {
			f, ok := toByte(n)
			if !ok {
				return "", false
			}
			b = append(b, f)
		}
		if len(b) == 64 && isASCIIDigitOrLowerHex(b) {
			return string(b), true
		}
		if len(b) == 32 {
			return hex.EncodeToString(b), true
		}
		return "", false
	case []byte:
		if len(val) == 64 && isASCIIDigitOrLowerHex(val) {
			return string(val), true
		}
		if len(val) == 32 {
			return hex.EncodeToString(val), true
		}
		return "", false
	}
	return "", false
}

func toByte(n interface{}) (byte, bool) {
	switch v := n.(type) {
	case float64:
		return byte(int(v)), v == float64(int(v)) && v >= 0 && v <= 255
	case int:
		return byte(v), v >= 0 && v <= 255
	case int64:
		return byte(v), v >= 0 && v <= 255
	}
	return 0, false
}

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return len(s) > 0
}

func isASCIIDigitOrLowerHex(b []byte) bool {
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
