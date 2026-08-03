package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const (
	testDomain  = "prove-it.app.preprod.enclava.dev"
	testLeafHex = "01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da"
	testReceipt = "05080b0e1114171a1d202326292c2f3235383b3e4144474a4d505356595c5f62"
	testReport  = "cf2b5bfe6f956590a7297b2d8fdd238b1a96eba3382c17ab9f5573b363dc57ad"
)

func testNonceB64(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	for i := 0; i < 32; i++ {
		b[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// fakeProxy returns an httptest server that mimics attestation-proxy
// /v1/attestation, embedding the given report_data in evidence.json.
func fakeProxy(t *testing.T, reportData string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok"})
			return
		case "/v1/attestation/info":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"attestation_type":  "coco-sev-snp",
				"runtime_class":     "kata-qemu-snp",
				"evidence_endpoint": "/v1/attestation?nonce=<base64-32B>&domain=<host>&leaf_spki_sha256=<hex>",
				"nonce_encoding":    "base64",
				"runtime_data_contract": map[string]interface{}{
					"caller_supplied_runtime_data": false,
					"report_data_layout":           "transcript_hash[32] || receipt_pubkey_sha256[32]",
				},
			})
			return
		case "/v1/attestation":
			// fall through to body below
		default:
			http.NotFound(w, r)
			return
		}
		body := map[string]interface{}{
			"version":          "1",
			"timestamp":        "2026-07-28T00:00:00Z",
			"attestation_type": "coco-sev-snp",
			"runtime_class":    "kata-qemu-snp",
			"nonce":            r.URL.Query().Get("nonce"),
			"runtime_data_binding": map[string]interface{}{
				"scheme":                "enclava-report-data-v1",
				"domain":                r.URL.Query().Get("domain"),
				"leaf_spki_sha256":      testLeafHex,
				"receipt_pubkey_sha256": testReceipt,
			},
			"evidence": map[string]interface{}{
				"format":      "coco-attestation-report",
				"payload_b64": "ZXhhbXBsZQ==",
				"json": map[string]interface{}{
					"attestation_report": map[string]interface{}{
						"report_data": reportData,
						"measurement": "abcdef",
					},
				},
				"content_type": "application/json",
			},
			"claims":              map[string]interface{}{"tee": "sev-snp"},
			"server_verification": map[string]interface{}{"verdict": "pass"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func newTestApp(t *testing.T, proxyURL string) *app {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".ready"), []byte("1"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "INSTANCE_LABEL"), []byte("ci"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "DEMO_SECRET"), []byte("hunter2"), 0o640); err != nil {
		t.Fatal(err)
	}
	a, err := newApp(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	a.proxy = &attestationProxyClient{
		httpURL:         proxyURL,
		tlsURL:          "",
		tlsSPKIOverride: testLeafHex,
		http:            http.DefaultClient,
	}
	return a
}

func TestVerify_MatchRevealsSecret(t *testing.T) {
	proxy := fakeProxy(t, testReport)
	defer proxy.Close()

	a := newTestApp(t, proxy.URL)
	body, _ := json.Marshal(verifyRequest{NonceB64: testNonceB64(t), Domain: testDomain})
	req := httptest.NewRequest(http.MethodPost, "/api/verify", bytes.NewReader(body))
	req.Host = testDomain
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp verifyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Match {
		t.Fatalf("Match = false; expected=%s evidence=%s src=%s",
			resp.ExpectedReportDataHex, resp.EvidenceReportDataHex, resp.EvidenceReportDataSource)
	}
	if !resp.Ok {
		t.Fatalf("Ok = false")
	}
	if resp.ExpectedReportDataHex != testReport {
		t.Fatalf("expected report_data = %s, want %s", resp.ExpectedReportDataHex, testReport)
	}
	if !resp.DemoSecretRevealed || resp.DemoSecret != "hunter2" {
		t.Fatalf("secret not revealed: revealed=%v secret=%q", resp.DemoSecretRevealed, resp.DemoSecret)
	}
	if resp.LeafSPKIResolution != "env" {
		t.Fatalf("leaf resolution = %q, want env", resp.LeafSPKIResolution)
	}
}

func TestVerify_MismatchHidesSecret(t *testing.T) {
	proxy := fakeProxy(t, "0000000000000000000000000000000000000000000000000000000000000000")
	defer proxy.Close()

	a := newTestApp(t, proxy.URL)
	body, _ := json.Marshal(verifyRequest{NonceB64: testNonceB64(t), Domain: testDomain})
	req := httptest.NewRequest(http.MethodPost, "/api/verify", bytes.NewReader(body))
	req.Host = testDomain
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)

	var resp verifyResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Match {
		t.Fatalf("Match = true, want false")
	}
	if resp.Ok {
		t.Fatalf("Ok = true, want false")
	}
	if resp.DemoSecretRevealed || resp.DemoSecret != "" {
		t.Fatalf("secret leaked on mismatch: %q", resp.DemoSecret)
	}
}

func TestAdversarialClaimsAreExplicitlyUntrustedAndOptIn(t *testing.T) {
	a := newTestApp(t, "http://127.0.0.1:1")
	for _, path := range []string{
		"/.well-known/confidential/proof-bundle",
		"/api/fake-appraiser",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, rec.Code)
		}
	}

	t.Setenv("PROVE_IT_ADVERSARIAL_DEMO", "1")
	req := httptest.NewRequest(http.MethodGet, "/api/fake-appraiser", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"verdict":"PASS"`)) ||
		!bytes.Contains(rec.Body.Bytes(), []byte("Untrusted opinion")) {
		t.Fatalf("unexpected fake appraiser response: %d %s", rec.Code, rec.Body.String())
	}
}

func TestVerify_MissingParams(t *testing.T) {
	proxy := fakeProxy(t, testReport)
	defer proxy.Close()

	a := newTestApp(t, proxy.URL)
	req := httptest.NewRequest(http.MethodPost, "/api/verify", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestVerify_RejectsPayloadDomainMismatch(t *testing.T) {
	proxy := fakeProxy(t, testReport)
	defer proxy.Close()

	a := newTestApp(t, proxy.URL)
	body, _ := json.Marshal(verifyRequest{NonceB64: testNonceB64(t), Domain: "attacker.example"})
	req := httptest.NewRequest(http.MethodPost, "/api/verify", bytes.NewReader(body))
	req.Host = testDomain
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !bytes.Contains(rec.Body.Bytes(), []byte(`"domain_mismatch"`)) {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestVerify_RejectsUnknownPayloadFields(t *testing.T) {
	proxy := fakeProxy(t, testReport)
	defer proxy.Close()

	a := newTestApp(t, proxy.URL)
	body := []byte(`{"nonce_b64":"` + testNonceB64(t) + `","domain":"` + testDomain + `","command":"whoami"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/verify", bytes.NewReader(body))
	req.Host = testDomain
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !bytes.Contains(rec.Body.Bytes(), []byte(`"bad_request"`)) {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestLivez(t *testing.T) {
	proxy := fakeProxy(t, testReport)
	defer proxy.Close()
	a := newTestApp(t, proxy.URL)

	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestInfoEndpoint(t *testing.T) {
	proxy := fakeProxy(t, testReport)
	defer proxy.Close()
	a := newTestApp(t, proxy.URL)

	req := httptest.NewRequest(http.MethodGet, "/api/info", nil)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp infoResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Runtime.ConfigReady {
		t.Fatalf("config_ready = false")
	}
	if !resp.Runtime.DemoSecretPresent || resp.Runtime.DemoSecretSHA256 == "" {
		t.Fatalf("demo secret not detected")
	}
	if resp.LeafSPKISha256 != testLeafHex {
		t.Fatalf("leaf spki = %s, want %s", resp.LeafSPKISha256, testLeafHex)
	}
	if resp.AttestationInfo == nil || resp.AttestationInfo["attestation_type"] != "coco-sev-snp" {
		t.Fatalf("attestation info not proxied")
	}
	if got := rec.Header().Get("Content-Security-Policy"); got == "" {
		t.Fatal("Content-Security-Policy header is missing")
	}
}

// TestVerify_FullHTTPServer stands both the app and the fake attestation-proxy
// behind real httptest listeners and drives the full /api/verify round trip with
// a real http.Client. This proves the live wiring (routing, embedded handler,
// real sockets) end to end, not just the handler under a recorder.
func TestVerify_FullHTTPServer(t *testing.T) {
	proxy := fakeProxy(t, testReport)
	defer proxy.Close()

	a := newTestApp(t, proxy.URL)
	appSrv := httptest.NewServer(a)
	defer appSrv.Close()

	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i) // golden nonce 0..31, matches fakeProxy's testReport
	}
	body, _ := json.Marshal(verifyRequest{
		NonceB64: base64.StdEncoding.EncodeToString(nonce),
		Domain:   testDomain,
	})

	req, err := http.NewRequest(http.MethodPost, appSrv.URL+"/api/verify", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Host = testDomain
	req.Header.Set("Content-Type", "application/json")
	resp, err := appSrv.Client().Do(req)
	if err != nil {
		t.Fatalf("http post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var vr verifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&vr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !vr.Ok || !vr.Match {
		t.Fatalf("ok=%v match=%v\nexpected=%s\nevidence=%s", vr.Ok, vr.Match, vr.ExpectedReportDataHex, vr.EvidenceReportDataHex)
	}
	if !vr.DemoSecretRevealed || vr.DemoSecret != "hunter2" {
		t.Fatalf("secret not revealed over real sockets: %q", vr.DemoSecret)
	}

	// /livez over real sockets too.
	livez, err := appSrv.Client().Get(appSrv.URL + "/livez")
	if err != nil {
		t.Fatalf("livez: %v", err)
	}
	if livez.StatusCode != http.StatusOK {
		t.Fatalf("livez status = %d", livez.StatusCode)
	}
	livez.Body.Close()
}
