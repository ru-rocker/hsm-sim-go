package main

// Section 9.1 - public-key / hybrid patterns: OpenPGP (gpg), JWE + RSA-PSS, age.

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// ============ Priority 1: OpenPGP via GnuPG ============

func gpg(home string, stdin []byte, args ...string) (stdout, stderr []byte, err error) {
	full := append([]string{"--homedir", home, "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", ""}, args...)
	cmd := exec.Command("gpg", full...)
	cmd.Stdin = bytes.NewReader(stdin)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if err := cmd.Run(); err != nil {
		return nil, se.Bytes(), fmt.Errorf("gpg %s: %w: %s", strings.Join(args, " "), err, se.String())
	}
	return so.Bytes(), se.Bytes(), nil
}

// algo: "rsa4096" (max interoperability) or "future-default" (Ed25519 + Curve25519)
func pgpGenKey(home, uid, algo string) error {
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	if strings.HasPrefix(algo, "rsa") { // primary = sign/cert, plus a separate encryption subkey
		if _, _, err := gpg(home, nil, "--quick-generate-key", uid, algo, "sign,cert", "never"); err != nil {
			return err
		}
		out, _, err := gpg(home, nil, "--with-colons", "--fingerprint", uid)
		if err != nil {
			return err
		}
		for _, l := range strings.Split(string(out), "\n") {
			if f := strings.Split(l, ":"); f[0] == "fpr" && len(f) > 9 {
				_, _, err = gpg(home, nil, "--quick-add-key", f[9], algo, "encr", "never")
				return err
			}
		}
		return errors.New("fingerprint not found")
	}
	_, _, err := gpg(home, nil, "--quick-generate-key", uid, algo, "default", "never")
	return err
}

func pgpExportPub(home, uid string) ([]byte, error) {
	out, _, err := gpg(home, nil, "--export", uid)
	return out, err
}

func pgpImport(home string, pub []byte) error {
	_, _, err := gpg(home, pub, "--import")
	return err
}

func pgpEncryptSign(home, recipient, signer string, data []byte) ([]byte, error) {
	out, _, err := gpg(home, data, "--trust-model", "always", "--cipher-algo", "AES256",
		"--digest-algo", "SHA256", "-r", recipient, "-u", signer, "--sign", "--encrypt")
	return out, err
}

func pgpDecryptVerify(home string, blob []byte) ([]byte, error) {
	out, status, err := gpg(home, blob, "--status-fd", "2", "--decrypt")
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(status), "GOODSIG") {
		return nil, errors.New("signature not valid")
	}
	return out, nil
}

// ============ Priority 2: JWE (RSA-OAEP-256 + A256GCM) with RSA-PSS signature ============

var b64u = base64.RawURLEncoding

func jweEncrypt(pub *rsa.PublicKey, pt []byte, kid string) (string, error) {
	hj, _ := json.Marshal(map[string]string{"alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": kid})
	hdr := b64u.EncodeToString(hj)
	cek, iv := randBytes(32), randBytes(12) // fresh CEK per message
	ek, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, cek, nil)
	if err != nil {
		return "", err
	}
	blk, _ := aes.NewCipher(cek)
	g, _ := cipher.NewGCM(blk)
	sealed := g.Seal(nil, iv, pt, []byte(hdr)) // protected header = AAD
	ct, tag := sealed[:len(sealed)-16], sealed[len(sealed)-16:]
	return strings.Join([]string{hdr, b64u.EncodeToString(ek), b64u.EncodeToString(iv),
		b64u.EncodeToString(ct), b64u.EncodeToString(tag)}, "."), nil
}

func jweDecrypt(priv *rsa.PrivateKey, token string) ([]byte, error) {
	p := strings.Split(token, ".")
	if len(p) != 5 {
		return nil, errors.New("bad JWE")
	}
	var raw [4][]byte
	for i := 0; i < 4; i++ {
		b, err := b64u.DecodeString(p[i+1])
		if err != nil {
			return nil, err
		}
		raw[i] = b
	}
	cek, err := rsa.DecryptOAEP(sha256.New(), nil, priv, raw[0], nil)
	if err != nil {
		return nil, err
	}
	blk, _ := aes.NewCipher(cek)
	g, _ := cipher.NewGCM(blk)
	ctTag := append(append([]byte{}, raw[2]...), raw[3]...)
	return g.Open(nil, raw[1], ctTag, []byte(p[0]))
}

func pssOpts() *rsa.PSSOptions { return &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash} }

func pssSign(priv *rsa.PrivateKey, msg []byte) ([]byte, error) {
	d := sha256.Sum256(msg)
	return rsa.SignPSS(rand.Reader, priv, crypto.SHA256, d[:], pssOpts())
}

func pssVerify(pub *rsa.PublicKey, msg, sig []byte) error {
	d := sha256.Sum256(msg)
	return rsa.VerifyPSS(pub, crypto.SHA256, d[:], sig, pssOpts())
}

// ============ Priority 3: age ============

const ageMagic = "age-style-v1"

// Teaching version of age: X25519 -> HKDF -> wrap 16-byte file key -> ChaCha20-Poly1305 STREAM.
// NOT byte-compatible with the real tool; see ageCLIRoundtrip for the real binary.
func ageStyleEncrypt(rpub *ecdh.PublicKey, data []byte, chunk int) ([]byte, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(rpub)
	if err != nil {
		return nil, err
	}
	salt := append(append([]byte{}, eph.PublicKey().Bytes()...), rpub.Bytes()...)
	wrapKey, err := hkdf.Key(sha256.New, shared, salt, "age-encryption.org/v1/X25519", 32)
	if err != nil {
		return nil, err
	}
	wa, _ := chacha20poly1305.New(wrapKey)
	fileKey := randBytes(16)
	wrapped := wa.Seal(nil, make([]byte, 12), fileKey, nil) // wrap key is single-use => fixed nonce OK
	n := randBytes(16)                                      // HKDF salt for payload key
	header := append(append(append([]byte(ageMagic), eph.PublicKey().Bytes()...), wrapped...), n...)
	pk, err := hkdf.Key(sha256.New, fileKey, n, "payload", 32)
	if err != nil {
		return nil, err
	}
	pa, _ := chacha20poly1305.New(pk)
	return append(header, streamEncrypt(pa, data, chunk, header)...), nil
}

func ageStyleDecrypt(rpriv *ecdh.PrivateKey, blob []byte, chunk int) ([]byte, error) {
	m := len(ageMagic)
	if len(blob) < m+80 {
		return nil, errors.New("too short")
	}
	epubB, wrapped, n := blob[m:m+32], blob[m+32:m+64], blob[m+64:m+80]
	header, body := blob[:m+80], blob[m+80:]
	epub, err := ecdh.X25519().NewPublicKey(epubB)
	if err != nil {
		return nil, err
	}
	shared, err := rpriv.ECDH(epub)
	if err != nil {
		return nil, err
	}
	salt := append(append([]byte{}, epubB...), rpriv.PublicKey().Bytes()...)
	wrapKey, err := hkdf.Key(sha256.New, shared, salt, "age-encryption.org/v1/X25519", 32)
	if err != nil {
		return nil, err
	}
	wa, _ := chacha20poly1305.New(wrapKey)
	fileKey, err := wa.Open(nil, make([]byte, 12), wrapped, nil)
	if err != nil {
		return nil, err
	}
	pk, err := hkdf.Key(sha256.New, fileKey, n, "payload", 32)
	if err != nil {
		return nil, err
	}
	pa, _ := chacha20poly1305.New(pk)
	return streamDecrypt(pa, body, chunk, header)
}

// Real age binary (installed in the Docker image). Returns (nil, nil) if not installed.
func ageCLIRoundtrip(data []byte) ([]byte, error) {
	if _, err := exec.LookPath("age"); err != nil {
		return nil, nil
	}
	if _, err := exec.LookPath("age-keygen"); err != nil {
		return nil, nil
	}
	dir, err := os.MkdirTemp("", "age")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	keyFile := dir + "/key.txt"
	if out, err := exec.Command("age-keygen", "-o", keyFile).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("age-keygen: %w: %s", err, out)
	}
	kb, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	pub := ""
	for _, l := range strings.Split(string(kb), "\n") {
		if strings.HasPrefix(l, "# public key: ") {
			pub = strings.TrimSpace(strings.TrimPrefix(l, "# public key: "))
		}
	}
	if pub == "" {
		return nil, errors.New("age public key not found")
	}
	enc := exec.Command("age", "-r", pub)
	enc.Stdin = bytes.NewReader(data)
	ct, err := enc.Output()
	if err != nil {
		return nil, fmt.Errorf("age encrypt: %w", err)
	}
	dec := exec.Command("age", "-d", "-i", keyFile)
	dec.Stdin = bytes.NewReader(ct)
	return dec.Output()
}
