package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

func decodeJSON(r *http.Request, v any) error {
	const maxBody = 1 << 16
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxBody {
		return errors.New("request body exceeds 64 KiB")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
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
