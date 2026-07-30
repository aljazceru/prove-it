package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

func errNonceLen(n int) error {
	return fmt.Errorf("nonce must be 32 bytes after base64 decode, got %d", n)
}
func errLen(expect, got int) error {
	return fmt.Errorf("expected %d bytes, got %d", expect, got)
}
