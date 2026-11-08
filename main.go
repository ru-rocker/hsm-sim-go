package main

// Runs every pattern from section 9 end-to-end and asserts that it works AND that tampering is caught.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const outDir = "out" // every demo result is written here

func ok(s string)  { fmt.Printf("  [OK]   %s\n", s) }
func hdr(s string) { fmt.Printf("\n=== %s ===\n", s) }
func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
func check(cond bool, msg string) {
	if !cond {
		log.Fatalf("CHECK FAILED: %s", msg)
	}
}
func mustFail(label string, fn func() error) {
	if err := fn(); err == nil {
		log.Fatalf("tamper NOT detected: %s", label)
	}
	ok("tamper detected: " + label)
}
func dec(blob []byte, k KEK) error { _, _, err := Decrypt(blob, k); return err }

func saveFile(name string, b []byte) string {
	must(os.MkdirAll(outDir, 0o755))
	p := filepath.Join(outDir, name)
	must(os.WriteFile(p, b, 0o600))
	fmt.Printf("  [DISK] wrote %s (%d bytes)\n", p, len(b))
	return p
}

// write to disk, then read back from disk, so the test proves the file on disk is what gets decrypted
func saveAndReload(name string, b []byte) []byte {
	back, err := os.ReadFile(saveFile(name, b))
	must(err)
	return back
}

func runDemo() error {
	kek, err := getKEK()
	must(err)
	fmt.Println("KEK provider:", kek.Name())

	meta := Meta{Filename: "settlement_2026-11-07.csv", Classification: "Restricted", Partner: "partner-A"}
	data := append([]byte("PAN,AMOUNT\n"), []byte(hex.EncodeToString(randBytes(150_000)))...) // ~300 KB, barely compressible
	saveFile("plain.csv", data)

	// ---------------- 9.2 symmetric ----------------
	hdr("9.2 Symmetric file encryption (DEK per file, wrapped by KEK in HSM/Vault)")
	for _, alg := range []string{AlgGCM, AlgChaCha, AlgCBC} {
		blob, err := Encrypt(data, kek, alg, meta, 64*1024)
		must(err)
		blob = saveAndReload("sym-"+alg+".enc", blob)
		plain, h, err := Decrypt(blob, kek)
		must(err)
		check(bytes.Equal(plain, data) && h.Meta == meta, alg+" round trip")
		saveFile("sym-"+alg+".dec", plain)
		ok(fmt.Sprintf("%s: %d -> %d bytes, round-trip", alg, len(data), len(blob)))
		bad := append([]byte{}, blob...)
		bad[len(bad)-40] ^= 1
		mustFail(alg+" bit flip", func() error { return dec(bad, kek) })
	}
	blob, err := Encrypt(data, kek, AlgGCM, meta, 4096)
	must(err)
	step := 4096 + 16
	mustFail("chunk truncation (final-chunk flag)", func() error { return dec(blob[:len(blob)-step], kek) })
	mustFail("AAD: header edited (partner-A -> partner-B)", func() error {
		return dec(bytes.Replace(blob, []byte("partner-A"), []byte("partner-B"), 1), kek)
	})
	must(kek.Rotate())
	check(dec(blob, kek) == nil, "decrypt after rotation")
	ok("KEK rotated; old files still decrypt (Vault keeps old key versions)")

	// ---------------- 9.1 asymmetric / hybrid ----------------
	hdr("9.1 (1) OpenPGP (GnuPG): AES-256 payload, RSA-4096 key exchange, SHA-256 signature")
	if _, err := exec.LookPath("gpg"); err != nil {
		fmt.Println("  [SKIP] gpg not installed (present in the Docker image)")
	} else {
		tmp, err := os.MkdirTemp("", "pgp")
		must(err)
		defer os.RemoveAll(tmp)
		me, partner := tmp+"/me", tmp+"/partner"
		t := time.Now()
		must(pgpGenKey(me, "bank@example.com", "rsa4096"))
		must(pgpGenKey(partner, "partner-a@example.com", "rsa4096"))
		ok(fmt.Sprintf("RSA-4096 keys generated (%.1fs) - partner private key stays in partner keyring", time.Since(t).Seconds()))
		pp, err := pgpExportPub(partner, "partner-a@example.com")
		must(err)
		mp, err := pgpExportPub(me, "bank@example.com")
		must(err)
		must(pgpImport(me, pp))
		must(pgpImport(partner, mp))
		enc, err := pgpEncryptSign(me, "partner-a@example.com", "bank@example.com", data)
		must(err)
		enc = saveAndReload("pgp-rsa4096.pgp", enc)
		plain, err := pgpDecryptVerify(partner, enc)
		must(err)
		saveFile("pgp.dec", plain)
		check(bytes.Equal(plain, data), "pgp round trip")
		ok("encrypt (partner pub) + sign (our key) -> decrypt + GOODSIG")
		bad := append([]byte{}, enc...)
		bad[100] ^= 1
		mustFail("PGP bit flip", func() error { _, err := pgpDecryptVerify(partner, bad); return err })
	}

	hdr("9.1 (2) JWE RSA-OAEP-256 + A256GCM, signed with RSA-PSS")
	partnerKey, err := rsa.GenerateKey(rand.Reader, 3072)
	must(err)
	senderKey, err := rsa.GenerateKey(rand.Reader, 3072)
	must(err)
	tok, err := jweEncrypt(&partnerKey.PublicKey, data[:2000], "partner-1")
	must(err)
	tok = string(saveAndReload("jwe.jwe", []byte(tok)))
	pt, err := jweDecrypt(partnerKey, tok)
	must(err)
	saveFile("jwe.dec", pt)
	check(bytes.Equal(pt, data[:2000]), "jwe round trip")
	sig, err := pssSign(senderKey, []byte(tok))
	must(err)
	must(pssVerify(&senderKey.PublicKey, []byte(tok), sig))
	saveFile("jwe.sig", sig)
	ok("JWE encrypt/decrypt + RSA-PSS sign/verify")
	mustFail("JWE header swap", func() error {
		_, err := jweDecrypt(partnerKey, "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoieCJ9"+tok[bytes.IndexByte([]byte(tok), '.'):])
		return err
	})
	mustFail("signature on modified JWE", func() error { return pssVerify(&senderKey.PublicKey, []byte(tok+"x"), sig) })

	hdr("9.1 (3) age (X25519 + ChaCha20-Poly1305)")
	rk, err := ecdh.X25519().GenerateKey(rand.Reader)
	must(err)
	ab, err := ageStyleEncrypt(rk.PublicKey(), data, 8192)
	must(err)
	ab = saveAndReload("age-style.age", ab)
	ap, err := ageStyleDecrypt(rk, ab, 8192)
	must(err)
	saveFile("age-style.dec", ap)
	check(bytes.Equal(ap, data), "age-style round trip")
	ok("age-style round-trip (teaching implementation)")
	realAge, err := ageCLIRoundtrip(data)
	must(err)
	if realAge == nil {
		fmt.Println("  [SKIP] `age` binary not installed (present in the Docker image)")
	} else {
		check(bytes.Equal(realAge, data), "age cli round trip")
		ok("real `age` binary round-trip")
	}

	// ---------------- 9.3 sharing keys ----------------
	hdr("9.3 (1) Preferred: wrap DEK to partner public key")
	dek := randBytes(32)
	w, err := wrapDEKForPartner(&partnerKey.PublicKey, dek)
	must(err)
	w = saveAndReload("partner-wrapped-dek.bin", w)
	u, err := unwrapDEKAsPartner(partnerKey, w)
	must(err)
	check(bytes.Equal(u, dek), "dek unwrap")
	ok("DEK wrapped with RSA-OAEP-256; only partner private key can unwrap")

	hdr("9.3 (2) Pre-shared key: HSM-generated, split under dual control, HKDF per file")
	master, err := kek.Random(32) // generated INSIDE Vault (transit/random) when Docker is used
	must(err)
	shares := xorSplit(master, 3)
	check(bytes.Equal(xorCombine(shares), master), "3 of 3 shares combine")
	check(!bytes.Equal(xorCombine(shares[:2]), master), "2 of 3 must not combine")
	ok("3 of 3 shares rebuild the key; 2 of 3 reveal nothing (dual/triple control)")
	h1, c1, err := pskEncrypt(data[:1000], master, "partner-A", "f1.csv")
	must(err)
	h1 = saveAndReload("psk.hdr.json", h1)
	c1 = saveAndReload("psk.enc", c1)
	_, c2, err := pskEncrypt(data[:1000], master, "partner-A", "f1.csv")
	must(err)
	p1, err := pskDecrypt(h1, c1, master)
	must(err)
	saveFile("psk.dec", p1)
	check(!bytes.Equal(c1, c2) && bytes.Equal(p1, data[:1000]), "psk")
	ok("same file encrypted twice -> different salt -> different key & ciphertext")
	mustFail("wrong partner in header", func() error {
		_, err := pskDecrypt(bytes.Replace(h1, []byte("partner-A"), []byte("partner-B"), 1), c1, master)
		return err
	})

	hdr("9.3 (3) Passphrase based (weakest) - salt demonstrated")
	const pass = "correct horse battery staple"
	for _, name := range []string{"argon2id", "scrypt", "pbkdf2"} {
		t := time.Now()
		h, c, err := passphraseEncrypt(data[:1000], pass, name)
		must(err)
		packed := saveAndReload("pass-"+name+".penc", packPass(h, c))
		h, c, err = unpackPass(packed)
		must(err)
		p, err := passphraseDecrypt(h, c, pass)
		must(err)
		saveFile("pass-"+name+".dec", p)
		check(bytes.Equal(p, data[:1000]), name+" round trip")
		ok(fmt.Sprintf("%s: derive+encrypt+decrypt in %.2fs (salt + params stored in header)", name, time.Since(t).Seconds()))
		mustFail(name+" wrong passphrase", func() error { _, err := passphraseDecrypt(h, c, "wrong"); return err })
	}
	sd, err := saltDemo("Summer2026!")
	must(err)
	for _, k := range []string{"unsalted SHA-256, run 1", "unsalted SHA-256, run 2", "salted PBKDF2, salt A", "salted PBKDF2, salt B"} {
		fmt.Printf("  %-26s: %s\n", k, sd[k])
	}
	fmt.Println("  (unsalted runs are identical => rainbow-table-able; salted keys differ for the same password)")

	fmt.Println("\nAll checks passed. Files written to ./" + outDir)
	return nil
}
