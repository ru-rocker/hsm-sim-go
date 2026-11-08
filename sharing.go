package main

// Section 9.3 - sharing keys with a partner, and salt.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

var b64 = base64.StdEncoding

// ---- 9.3 (1) PREFERRED: wrap each file's DEK to the partner public key (no shared secret) ----

func wrapDEKForPartner(pub *rsa.PublicKey, dek []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, dek, nil)
}

func unwrapDEKAsPartner(priv *rsa.PrivateKey, w []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), nil, priv, w, nil)
}

// ---- 9.3 (2) pre-shared symmetric key: HSM-generated, split, HKDF per file ----

// n-of-n XOR split (dual/triple control): all shares needed, any n-1 reveal nothing.
// For k-of-n use Shamir (what Vault's unseal keys do).
func xorSplit(secret []byte, n int) [][]byte {
	shares := make([][]byte, 0, n)
	last := append([]byte{}, secret...)
	for i := 0; i < n-1; i++ {
		s := randBytes(len(secret))
		for j := range last {
			last[j] ^= s[j]
		}
		shares = append(shares, s)
	}
	return append(shares, last)
}

func xorCombine(shares [][]byte) []byte {
	out := make([]byte, len(shares[0]))
	for _, s := range shares {
		for j := range out {
			out[j] ^= s[j]
		}
	}
	return out
}

type PSKHeader struct {
	KDF      string `json:"kdf"`
	Salt     string `json:"salt"`
	Nonce    string `json:"nonce"`
	Partner  string `json:"partner"`
	Filename string `json:"filename"`
}

func pskKey(master, salt []byte, partner, filename string) ([]byte, error) {
	return hkdf.Key(sha256.New, master, salt, "psk|"+partner+"|"+filename, 32)
}

func pskEncrypt(data, master []byte, partner, filename string) (hdr, ct []byte, err error) {
	salt := randBytes(32) // fresh per file => unique key per file
	key, err := pskKey(master, salt, partner, filename)
	if err != nil {
		return nil, nil, err
	}
	n := randBytes(12)
	hdr, _ = json.Marshal(PSKHeader{"HKDF-SHA256", b64.EncodeToString(salt), b64.EncodeToString(n), partner, filename})
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	return hdr, g.Seal(nil, n, data, hdr), nil
}

func pskDecrypt(hdr, ct, master []byte) ([]byte, error) {
	var h PSKHeader
	if err := json.Unmarshal(hdr, &h); err != nil {
		return nil, err
	}
	salt, err1 := b64.DecodeString(h.Salt)
	n, err2 := b64.DecodeString(h.Nonce)
	if err1 != nil || err2 != nil {
		return nil, errors.New("bad header")
	}
	key, err := pskKey(master, salt, h.Partner, h.Filename)
	if err != nil {
		return nil, err
	}
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	return g.Open(nil, n, ct, hdr)
}

// ---- 9.3 (3) passphrase based (weakest): password KDFs + random salt ----

type KDFParams struct {
	Time    uint32 `json:"t,omitempty"`    // argon2id passes
	MemKiB  uint32 `json:"m,omitempty"`    // argon2id memory
	Threads uint8  `json:"p,omitempty"`    // argon2id lanes
	N       int    `json:"n,omitempty"`    // scrypt cost
	R       int    `json:"r,omitempty"`    // scrypt block size
	P       int    `json:"sp,omitempty"`   // scrypt parallelism
	Iter    int    `json:"iter,omitempty"` // pbkdf2 iterations
}

func defaultParams(name string) KDFParams {
	switch name {
	case "argon2id": // memory-hard (preferred): 64 MiB, 3 passes, 4 lanes
		return KDFParams{Time: 3, MemKiB: 64 * 1024, Threads: 4}
	case "scrypt": // memory-hard
		return KDFParams{N: 1 << 15, R: 8, P: 1}
	default: // pbkdf2: minimum acceptable, CPU-only
		return KDFParams{Iter: 600_000}
	}
}

func deriveKey(name, pw string, salt []byte, p KDFParams) ([]byte, error) {
	switch name {
	case "argon2id":
		return argon2.IDKey([]byte(pw), salt, p.Time, p.MemKiB, p.Threads, 32), nil
	case "scrypt":
		return scrypt.Key([]byte(pw), salt, p.N, p.R, p.P, 32)
	case "pbkdf2":
		return pbkdf2.Key(sha256.New, pw, salt, p.Iter, 32)
	}
	return nil, fmt.Errorf("unknown kdf %q", name)
}

type PassHeader struct {
	KDF    string    `json:"kdf"`
	Params KDFParams `json:"params"`
	Salt   string    `json:"salt"`
	Nonce  string    `json:"nonce"`
}

func passphraseEncrypt(data []byte, pass, name string) (hdr, ct []byte, err error) {
	salt := randBytes(16) // >=128-bit random, unique per file, NOT secret
	p := defaultParams(name)
	key, err := deriveKey(name, pass, salt, p)
	if err != nil {
		return nil, nil, err
	}
	n := randBytes(12)
	hdr, _ = json.Marshal(PassHeader{name, p, b64.EncodeToString(salt), b64.EncodeToString(n)})
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	return hdr, g.Seal(nil, n, data, hdr), nil
}

func passphraseDecrypt(hdr, ct []byte, pass string) ([]byte, error) {
	var h PassHeader
	if err := json.Unmarshal(hdr, &h); err != nil {
		return nil, err
	}
	salt, err1 := b64.DecodeString(h.Salt)
	n, err2 := b64.DecodeString(h.Nonce)
	if err1 != nil || err2 != nil {
		return nil, errors.New("bad header")
	}
	key, err := deriveKey(h.KDF, pass, salt, h.Params) // salt + params come from the header
	if err != nil {
		return nil, err
	}
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	return g.Open(nil, n, ct, hdr)
}

// Why salt matters
func saltDemo(pw string) (map[string]string, error) {
	u := sha256.Sum256([]byte(pw))
	k1, err := deriveKey("pbkdf2", pw, randBytes(16), defaultParams("pbkdf2"))
	if err != nil {
		return nil, err
	}
	k2, err := deriveKey("pbkdf2", pw, randBytes(16), defaultParams("pbkdf2"))
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"unsalted SHA-256, run 1": hex.EncodeToString(u[:16]),
		"unsalted SHA-256, run 2": hex.EncodeToString(u[:16]),
		"salted PBKDF2, salt A":   hex.EncodeToString(k1[:16]),
		"salted PBKDF2, salt B":   hex.EncodeToString(k2[:16]),
	}, nil
}
