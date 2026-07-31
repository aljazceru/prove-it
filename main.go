// Command prove-it is a self-describing attestation dashboard. It runs inside
// a confidential workload, mediates the co-located attestation-proxy, and lets
// a browser cryptographically verify that it is talking to a live, attested
// AMD SEV-SNP confidential VM whose attestation report is bound to the current
// session nonce, the tenant domain, and the in-TEE TLS identity.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("addr", envOr("PROVE_IT_ADDR", ":8080"), "HTTP listen address")
	configDir := flag.String("config-dir",
		envOr("ENCLAVA_CONFIG_DIR", "/state/.enclava/config"),
		"Enclava confidential config handoff directory")
	statePath := flag.String("state-path",
		envOr("ENCLAVA_STATE_PATH", "/state/app-data"),
		"Encrypted state volume path")
	flag.Parse()

	globalConfigDir = *configDir

	app, err := newApp(*configDir, *statePath)
	if err != nil {
		log.Fatalf("prove-it: init failed: %v", err)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           app,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("prove-it %s listening on %s (config-dir=%s state-path=%s)",
			proveItVersion, *addr, *configDir, *statePath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("prove-it: server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Printf("prove-it: shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("prove-it: shutdown error: %v", err)
	}
}
