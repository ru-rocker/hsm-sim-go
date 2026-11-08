package main

// KEK providers = the "HSM" of this simulation.
//   VaultKEK : HashiCorp Vault Transit (Docker). The KEK never leaves Vault; the app only sees wrapped DEKs.
//   SoftKEK  : in-memory stand-in with the same interface (runs without Docker).
// Every wrapped DEK is bound to a context (partner|classification|version).

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type KEK interface {
	Name() string
	KID() string
	GenerateDataKey(ctx []byte) (dek, wrapped []byte, err error) // ~ KMS GenerateDataKey
	Unwrap(wrapped, ctx []byte) ([]byte, error)
	Random(n int) ([]byte, error)
	Rotate() error
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// ---------------- SoftKEK ----------------

type SoftKEK struct{ key []byte }

func NewSoftKEK() *SoftKEK { return &SoftKEK{key: randBytes(32)} }

func (s *SoftKEK) Name() string { return "SoftKEK (in-memory, tests only)" }
func (s *SoftKEK) KID() string  { return "soft-kek:v1" }

func (s *SoftKEK) gcm() cipher.AEAD {
	blk, _ := aes.NewCipher(s.key)
	g, _ := cipher.NewGCM(blk)
	return g
}

func (s *SoftKEK) GenerateDataKey(ctx []byte) ([]byte, []byte, error) {
	dek := randBytes(32)
	g := s.gcm()
	n := randBytes(g.NonceSize())
	return dek, g.Seal(n, n, dek, ctx), nil // nonce || ciphertext
}

func (s *SoftKEK) Unwrap(w, ctx []byte) ([]byte, error) {
	g := s.gcm()
	if len(w) < g.NonceSize() {
		return nil, fmt.Errorf("wrapped key too short")
	}
	return g.Open(nil, w[:g.NonceSize()], w[g.NonceSize():], ctx)
}

func (s *SoftKEK) Random(n int) ([]byte, error) { return randBytes(n), nil }
func (s *SoftKEK) Rotate() error                { return nil }

// ---------------- VaultKEK (Transit engine) ----------------

type VaultKEK struct {
	addr, token, key string
	client           *http.Client
}

func NewVaultKEK(addr, token, key string) (*VaultKEK, error) {
	v := &VaultKEK{addr: addr, token: token, key: key, client: &http.Client{Timeout: 10 * time.Second}}
	// enable transit (error if already enabled is fine); then create a derived AES-256 key.
	// Retried because Vault needs a moment to become active after unseal.
	var err error
	for i := 0; i < 20; i++ {
		_, _ = v.post("sys/mounts/transit", map[string]any{"type": "transit"})
		_, err = v.post("transit/keys/"+key, map[string]any{"type": "aes256-gcm96", "derived": true})
		if err == nil {
			return v, nil
		}
		time.Sleep(time.Second)
	}
	return nil, fmt.Errorf("cannot reach Vault at %s: %w", addr, err)
}

func (v *VaultKEK) Name() string { return "Vault Transit (docker)" }
func (v *VaultKEK) KID() string  { return "vault-transit:" + v.key }

func (v *VaultKEK) post(path string, body any) (map[string]any, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", v.addr+"/v1/"+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", v.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vault %s: %d %s", path, resp.StatusCode, string(data))
	}
	if len(data) == 0 {
		return nil, nil
	}
	var out struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

func str(m map[string]any, k string) (string, error) {
	s, ok := m[k].(string)
	if !ok {
		return "", fmt.Errorf("vault response missing %q", k)
	}
	return s, nil
}

func (v *VaultKEK) GenerateDataKey(ctx []byte) ([]byte, []byte, error) {
	d, err := v.post("transit/datakey/plaintext/"+v.key, map[string]any{
		"context": base64.StdEncoding.EncodeToString(ctx), "bits": 256})
	if err != nil {
		return nil, nil, err
	}
	pt, err := str(d, "plaintext")
	if err != nil {
		return nil, nil, err
	}
	ct, err := str(d, "ciphertext")
	if err != nil {
		return nil, nil, err
	}
	dek, err := base64.StdEncoding.DecodeString(pt)
	return dek, []byte(ct), err // wrapped = "vault:v1:..."
}

func (v *VaultKEK) Unwrap(wrapped, ctx []byte) ([]byte, error) {
	d, err := v.post("transit/decrypt/"+v.key, map[string]any{
		"ciphertext": string(wrapped), "context": base64.StdEncoding.EncodeToString(ctx)})
	if err != nil {
		return nil, err
	}
	pt, err := str(d, "plaintext")
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(pt)
}

// Random: entropy generated inside Vault
func (v *VaultKEK) Random(n int) ([]byte, error) {
	d, err := v.post(fmt.Sprintf("transit/random/%d", n), map[string]any{"format": "base64"})
	if err != nil {
		return nil, err
	}
	s, err := str(d, "random_bytes")
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(s)
}

// Rotate: new KEK version; old versions still decrypt, old files need no re-encryption
func (v *VaultKEK) Rotate() error {
	_, err := v.post("transit/keys/"+v.key+"/rotate", map[string]any{})
	return err
}

func getKEK() (KEK, error) {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		return NewSoftKEK(), nil
	}
	tok := os.Getenv("VAULT_TOKEN") // optional; normally empty -> token comes from vault-init.json
	if tok == "" {
		var err error
		if tok, err = vaultEnsureReady(addr, initFilePath()); err != nil {
			return nil, err
		}
	}
	return NewVaultKEK(addr, tok, "kek")
}
