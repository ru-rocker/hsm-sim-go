package main

// Section 9.2 - symmetric file encryption. Key per file, wrapped by the KEK (HSM/Vault).
// Container:  "HSMF1" | uint32 len(header) | header(JSON) | body
// The header bytes are used as AAD (AEAD) or as MAC input (CBC+HMAC).
// Order: compress -> encrypt (-> sign, see main.go).

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	magic     = "HSMF1"
	version   = 1
	AlgGCM    = "AES-256-GCM"
	AlgChaCha = "CHACHA20-POLY1305"
	AlgCBC    = "AES-256-CBC-HMAC"
)

type Meta struct {
	Filename       string `json:"filename"`
	Classification string `json:"classification"`
	Partner        string `json:"partner"`
}

type Header struct {
	V     int    `json:"v"`
	Alg   string `json:"alg"`
	KID   string `json:"kid"`
	WDEK  string `json:"wdek"`
	Chunk int    `json:"chunk"`
	Meta
}

func keyCtx(m Meta) []byte {
	return []byte(fmt.Sprintf("%s|%s|v%d", m.Partner, m.Classification, version))
}

// 96-bit nonce = 11-byte big-endian chunk counter || 1-byte "final chunk" flag (age STREAM style)
func nonce(i int, last bool) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[3:11], uint64(i))
	if last {
		n[11] = 1
	}
	return n
}

func streamEncrypt(a cipher.AEAD, data []byte, chunk int, aad []byte) []byte {
	count := (len(data) + chunk - 1) / chunk
	if count == 0 {
		count = 1
	}
	var out []byte
	for i := 0; i < count; i++ {
		lo := i * chunk
		hi := min(lo+chunk, len(data))
		out = a.Seal(out, nonce(i, i == count-1), data[lo:hi], aad)
	}
	return out
}

func streamDecrypt(a cipher.AEAD, body []byte, chunk int, aad []byte) ([]byte, error) {
	step := chunk + a.Overhead()
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}
	n := (len(body) + step - 1) / step
	var out []byte
	for i := 0; i < n; i++ {
		part := body[i*step : min((i+1)*step, len(body))]
		// truncation => new last chunk was sealed with flag=0 => authentication fails
		pt, err := a.Open(nil, nonce(i, i == n-1), part, aad)
		if err != nil {
			return nil, fmt.Errorf("chunk %d: %w", i, err)
		}
		out = append(out, pt...)
	}
	return out, nil
}

func newAEAD(alg string, key []byte) (cipher.AEAD, error) {
	switch alg {
	case AlgGCM:
		blk, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(blk)
	case AlgChaCha:
		return chacha20poly1305.New(key)
	}
	return nil, errors.New("algorithm not approved")
}

func splitKeys(dek []byte) (enc, mac []byte, err error) {
	k, err := hkdf.Key(sha256.New, dek, nil, "cbc-hmac-split", 64)
	if err != nil {
		return nil, nil, err
	}
	return k[:32], k[32:], nil
}

func pkcs7Pad(b []byte) []byte {
	n := 16 - len(b)%16
	return append(append([]byte{}, b...), bytes.Repeat([]byte{byte(n)}, n)...)
}

func pkcs7Unpad(b []byte) ([]byte, error) {
	if len(b) == 0 || len(b)%16 != 0 {
		return nil, errors.New("bad padding")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > 16 || n > len(b) {
		return nil, errors.New("bad padding")
	}
	return b[:len(b)-n], nil
}

func deflate(b []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func inflate(b []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func Encrypt(data []byte, kek KEK, alg string, meta Meta, chunk int) ([]byte, error) {
	data = deflate(data) // compress BEFORE encrypt
	dek, wrapped, err := kek.GenerateDataKey(keyCtx(meta)) // fresh 256-bit DEK per file
	if err != nil {
		return nil, err
	}
	h := Header{V: version, Alg: alg, KID: kek.KID(),
		WDEK: base64.StdEncoding.EncodeToString(wrapped), Chunk: chunk, Meta: meta}
	hb, _ := json.Marshal(h)

	var out bytes.Buffer
	out.WriteString(magic)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(hb)))
	out.Write(l[:])
	out.Write(hb)

	switch alg {
	case AlgGCM, AlgChaCha: // priority 1 and 2
		a, err := newAEAD(alg, dek)
		if err != nil {
			return nil, err
		}
		out.Write(streamEncrypt(a, data, chunk, hb))
	case AlgCBC: // priority 3: compatibility fallback, encrypt-then-MAC
		ek, mk, err := splitKeys(dek)
		if err != nil {
			return nil, err
		}
		iv := randBytes(16)
		blk, _ := aes.NewCipher(ek)
		padded := pkcs7Pad(data)
		ct := make([]byte, len(padded))
		cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, padded)
		mac := hmac.New(sha256.New, mk)
		mac.Write(hb)
		mac.Write(iv)
		mac.Write(ct)
		out.Write(iv)
		out.Write(ct)
		out.Write(mac.Sum(nil))
	default:
		return nil, errors.New("algorithm not approved")
	}
	return out.Bytes(), nil
}

func Decrypt(blob []byte, kek KEK) ([]byte, Header, error) {
	var h Header
	if len(blob) < 9 || string(blob[:5]) != magic {
		return nil, h, errors.New("bad magic")
	}
	hl := int(binary.BigEndian.Uint32(blob[5:9]))
	if 9+hl > len(blob) {
		return nil, h, errors.New("bad header length")
	}
	hb, body := blob[9:9+hl], blob[9+hl:]
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, h, err
	}
	wrapped, err := base64.StdEncoding.DecodeString(h.WDEK)
	if err != nil {
		return nil, h, err
	}
	dek, err := kek.Unwrap(wrapped, keyCtx(h.Meta))
	if err != nil {
		return nil, h, fmt.Errorf("unwrap DEK: %w", err)
	}
	var data []byte
	switch h.Alg {
	case AlgGCM, AlgChaCha:
		a, err := newAEAD(h.Alg, dek)
		if err != nil {
			return nil, h, err
		}
		if data, err = streamDecrypt(a, body, h.Chunk, hb); err != nil {
			return nil, h, err
		}
	case AlgCBC:
		if len(body) < 16+16+32 {
			return nil, h, errors.New("body too short")
		}
		ek, mk, err := splitKeys(dek)
		if err != nil {
			return nil, h, err
		}
		iv, ct, tag := body[:16], body[16:len(body)-32], body[len(body)-32:]
		mac := hmac.New(sha256.New, mk)
		mac.Write(hb)
		mac.Write(iv)
		mac.Write(ct)
		if !hmac.Equal(tag, mac.Sum(nil)) { // verify BEFORE decrypting
			return nil, h, errors.New("MAC check failed")
		}
		if len(ct)%16 != 0 {
			return nil, h, errors.New("bad ciphertext length")
		}
		blk, _ := aes.NewCipher(ek)
		pt := make([]byte, len(ct))
		cipher.NewCBCDecrypter(blk, iv).CryptBlocks(pt, ct)
		if data, err = pkcs7Unpad(pt); err != nil {
			return nil, h, err
		}
	default:
		return nil, h, errors.New("algorithm not approved")
	}
	plain, err := inflate(data)
	return plain, h, err
}
