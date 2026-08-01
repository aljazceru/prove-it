package main

// Runtime probes: confidential config handoff, encrypted state volume, and TEE
// indicators. These let the dashboard honestly distinguish "running inside an
// attested confidential VM" from "running on a plain node".

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

// runtimeFacts is the snapshot surfaced at GET /api/info.
type runtimeFacts struct {
	ConfigDir         string    `json:"config_dir"`
	ConfigReady       bool      `json:"config_ready"`
	ConfigKeys        []string  `json:"config_keys"`
	InstanceLabel     string    `json:"instance_label"`
	DemoSecretPresent bool      `json:"demo_secret_present"`
	DemoSecretSHA256  string    `json:"demo_secret_sha256"`
	StatePath         string    `json:"state_path"`
	StateWritable     bool      `json:"state_writable"`
	TEEIndicators     []string  `json:"tee_indicators"`
	Hostname          string    `json:"hostname"`
	StartedAt         time.Time `json:"started_at"`
	Version           string    `json:"version"`
}

const proveItVersion = "0.2.1"

func gatherRuntimeFacts(configDir, statePath string) runtimeFacts {
	facts := runtimeFacts{
		ConfigDir: configDir,
		StatePath: statePath,
		Hostname:  hostname(),
		StartedAt: startTime,
		Version:   proveItVersion,
	}

	if ready, keys := scanConfig(configDir); ready != nil {
		facts.ConfigReady = *ready
		facts.ConfigKeys = keys
	}

	facts.InstanceLabel = firstNonEmpty(readConfigValue(configDir, "INSTANCE_LABEL"), os.Getenv("PROVE_IT_INSTANCE_LABEL"), "prove-it")
	if secret, ok := readConfigValueOk(configDir, "DEMO_SECRET"); ok && secret != "" {
		facts.DemoSecretPresent = true
		sum := sha256.Sum256([]byte(strings.TrimRight(secret, "\r\n")))
		facts.DemoSecretSHA256 = hex.EncodeToString(sum[:])
	}

	facts.StateWritable = probeStateWritable(statePath)
	facts.TEEIndicators = detectTEE()
	return facts
}

func readConfigValueOk(configDir, key string) (string, bool) {
	if configDir == "" {
		return "", false
	}
	b, err := os.ReadFile(filepath.Join(configDir, key))
	if err != nil {
		return "", false
	}
	return strings.TrimRight(string(b), "\r\n"), true
}

func readConfigValue(configDir, key string) string {
	v, _ := readConfigValueOk(configDir, key)
	return v
}

func scanConfig(configDir string) (*bool, []string) {
	if configDir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(configDir)
	if err != nil {
		ready := false
		return &ready, nil
	}
	keys := make([]string, 0, len(entries))
	ready := false
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if name == ".ready" {
			ready = true
			continue
		}
		if strings.HasPrefix(name, ".") {
			continue
		}
		keys = append(keys, name)
	}
	return &ready, keys
}

// probeStateWritable confirms the LUKS-backed /state volume is mounted and
// writable by writing, reading, and removing a sentinel file.
func probeStateWritable(statePath string) bool {
	if statePath == "" {
		return false
	}
	if err := os.MkdirAll(statePath, 0o750); err != nil {
		return false
	}
	probe := filepath.Join(statePath, ".prove-it-probe")
	defer os.Remove(probe)
	if err := os.WriteFile(probe, []byte("ok"), 0o640); err != nil {
		return false
	}
	b, err := os.ReadFile(probe)
	return err == nil && string(b) == "ok"
}

// detectTEE gathers best-effort signals. Authoritative proof still comes from a
// successful attestation; these indicators are informational only.
func detectTEE() []string {
	var out []string

	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		s := strings.ToLower(string(b))
		for _, flag := range []string{"sev", "snp", "tdx", "tee"} {
			if strings.Contains(s, flag) {
				out = append(out, "cpuinfo:"+flag)
			}
		}
	}

	for _, p := range []string{
		"/sys/module/kvm_amd",
		"/sys/module/kvm_intel",
		"/run/confidential-containers",
		"/run/image-rs",
		"/dev/sev",
	} {
		if _, err := os.Stat(p); err == nil {
			out = append(out, "path:"+p)
		}
	}

	if v := strings.TrimSpace(os.Getenv("PROVE_IT_TEE")); v != "" {
		out = append(out, "env:"+v)
	}
	return out
}

func hostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// startTime and startTime are set in main.go via init in this file.
var startTime = nowUTC()

func nowUTC() time.Time { return time.Now().UTC() }
