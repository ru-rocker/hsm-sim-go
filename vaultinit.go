package main

// Vault in server mode starts "uninitialised" and "sealed". This file does the one-time setup and the unseal
// after every restart, so you never type unseal keys by hand.
// SIMULATION ONLY: the unseal key and root token are saved in plain text in vault-init.json.
// In production the unseal key is protected by an HSM (or split between custodians) and root tokens are not used.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type initFile struct {
	UnsealKey string `json:"unseal_key"`
	RootToken string `json:"root_token"`
}

func initFilePath() string {
	if p := os.Getenv("VAULT_INIT_FILE"); p != "" {
		return p
	}
	return "vault-init.json"
}

func vaultCall(method, url string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %d %s", method, url, resp.StatusCode, string(data))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// vaultEnsureReady: initialise Vault if new, unseal it if sealed, return the root token.
func vaultEnsureReady(addr, path string) (string, error) {
	var st struct {
		Initialized bool `json:"initialized"`
		Sealed      bool `json:"sealed"`
	}
	var err error
	for i := 0; i < 30; i++ { // wait for the container to start
		if err = vaultCall("GET", addr+"/v1/sys/seal-status", nil, &st); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		return "", fmt.Errorf("cannot reach Vault at %s: %w", addr, err)
	}

	if !st.Initialized {
		var res struct {
			Keys      []string `json:"keys_base64"`
			RootToken string   `json:"root_token"`
		}
		err := vaultCall("POST", addr+"/v1/sys/init", map[string]any{"secret_shares": 1, "secret_threshold": 1}, &res)
		if err != nil {
			return "", err
		}
		if len(res.Keys) == 0 {
			return "", fmt.Errorf("vault init returned no unseal key")
		}
		b, _ := json.MarshalIndent(initFile{UnsealKey: res.Keys[0], RootToken: res.RootToken}, "", "  ")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return "", err
		}
		fmt.Println("Vault initialised. Unseal key + root token saved to", path, "(SIMULATION ONLY)")
		st.Sealed = true
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("vault is already initialised but %s is missing: %w", path, err)
	}
	var f initFile
	if err := json.Unmarshal(b, &f); err != nil {
		return "", err
	}
	if st.Sealed {
		if err := vaultCall("POST", addr+"/v1/sys/unseal", map[string]any{"key": f.UnsealKey}, nil); err != nil {
			return "", err
		}
		fmt.Println("Vault was sealed -> unsealed with the saved key")
	}
	return f.RootToken, nil
}
