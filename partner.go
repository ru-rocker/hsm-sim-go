package main

// Section 9.3 on real files.
// WAY 1 (preferred): partner RSA key pair. The DEK is wrapped with the partner's PUBLIC key.
//     go run . keygen       -name partner                          (partner runs this, sends the public key)
//     go run . wrap-encrypt -in F -pub keys/partner_public.pem     (you)
//     go run . wrap-decrypt -in F.wrap -priv keys/partner_private.pem   (partner)
// WAY 2: pre-shared master key, split into shares, HKDF + salt per file.
//     go run . psk-init -partner P ; psk-encrypt ; psk-decrypt
// WAY 3: passphrase -> see pass-encrypt / pass-decrypt in cli.go

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ---------- RSAKEK: partner public key in the "KEK" role ----------
// Same KEK interface as Vault, so Encrypt/Decrypt in sym.go work unchanged.
// The context (partner|classification|version) is bound in as the OAEP label.

type RSAKEK struct {
	pub  *rsa.PublicKey
	priv *rsa.PrivateKey // nil on the sender side
}

func (r *RSAKEK) Name() string { return "partner RSA key (RSA-OAEP-256)" }
func (r *RSAKEK) KID() string  { return "rsa-oaep-256:" + pubFingerprint(r.pub)[:16] }

func (r *RSAKEK) GenerateDataKey(ctx []byte) ([]byte, []byte, error) {
	dek := randBytes(32)
	w, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, r.pub, dek, ctx)
	if err != nil {
		return nil, nil, err
	}
	return dek, w, nil
}

func (r *RSAKEK) Unwrap(w, ctx []byte) ([]byte, error) {
	if r.priv == nil {
		return nil, errors.New("no private key loaded")
	}
	return rsa.DecryptOAEP(sha256.New(), nil, r.priv, w, ctx)
}

func (r *RSAKEK) Random(n int) ([]byte, error) { return randBytes(n), nil }
func (r *RSAKEK) Rotate() error                { return nil }

// ---------- key files ----------

func pubFingerprint(pub *rsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha256.Sum256(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func spaced(s string) string {
	var parts []string
	for i := 0; i < len(s); i += 4 {
		parts = append(parts, s[i:min(i+4, len(s))])
	}
	return strings.Join(parts, " ")
}

func loadPub(path string) (*rsa.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s is not a PEM file", path)
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return pub, nil
}

func loadPriv(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s is not a PEM file", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return priv, nil
}

// ---------- WAY 1 commands ----------

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	name := fs.String("name", "partner", "name used for the key files")
	dir := fs.String("dir", "keys", "folder for the key files")
	bits := fs.Int("bits", 3072, "RSA size: 3072 or 4096")
	force := fs.Bool("force", false, "overwrite existing key files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bits != 3072 && *bits != 4096 {
		return errors.New("-bits must be 3072 or 4096")
	}
	n := filepath.Base(*name)
	priv, err := rsa.GenerateKey(rand.Reader, *bits)
	if err != nil {
		return err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return err
	}
	privPath := filepath.Join(*dir, n+"_private.pem")
	pubPath := filepath.Join(*dir, n+"_public.pem")
	if err := writeNew(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), *force); err != nil {
		return err
	}
	if err := writeNew(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), *force); err != nil {
		return err
	}
	fmt.Printf("RSA-%d key pair created\n  PRIVATE (keep secret, never send): %s\n  PUBLIC  (safe to send):            %s\n  Public key fingerprint (SHA-256): %s\n",
		*bits, privPath, pubPath, spaced(pubFingerprint(&priv.PublicKey)))
	fmt.Println("  Read this fingerprint to the other side by phone so they can confirm the key is not fake.")
	return nil
}

func cmdWrapEncrypt(args []string) error {
	fs := flag.NewFlagSet("wrap-encrypt", flag.ContinueOnError)
	method := fs.String("method", "gcm", "gcm | chacha | cbc")
	in := fs.String("in", "", "file to encrypt")
	pubPath := fs.String("pub", "", "partner public key (PEM)")
	out := fs.String("out", "", "output file (default: <in>.wrap)")
	partner := fs.String("partner", "partner-A", "partner id (bound into the wrapped key)")
	class := fs.String("class", "Restricted", "classification (bound into the wrapped key)")
	force := fs.Bool("force", false, "overwrite output if it exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *pubPath == "" {
		return errors.New("-in and -pub are required")
	}
	alg, err := algFromName(*method)
	if err != nil {
		return err
	}
	pub, err := loadPub(*pubPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	meta := Meta{Filename: filepath.Base(*in), Classification: *class, Partner: *partner}
	blob, err := Encrypt(data, &RSAKEK{pub: pub}, alg, meta, 64*1024)
	if err != nil {
		return err
	}
	dst := *out
	if dst == "" {
		dst = *in + ".wrap"
	}
	if err := writeNew(dst, blob, *force); err != nil {
		return err
	}
	fmt.Printf("encrypted %s -> %s (%d bytes)\n  method=%s, DEK wrapped with the partner PUBLIC key\n  Partner key fingerprint: %s\n  (make sure this matches what the partner told you)\n",
		*in, dst, len(blob), alg, spaced(pubFingerprint(pub)))
	return nil
}

func cmdWrapDecrypt(args []string) error {
	fs := flag.NewFlagSet("wrap-decrypt", flag.ContinueOnError)
	in := fs.String("in", "", "encrypted file")
	privPath := fs.String("priv", "", "your private key (PEM)")
	out := fs.String("out", "", "output file (default: <in>.dec)")
	force := fs.Bool("force", false, "overwrite output if it exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *privPath == "" {
		return errors.New("-in and -priv are required")
	}
	priv, err := loadPriv(*privPath)
	if err != nil {
		return err
	}
	blob, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	plain, h, err := Decrypt(blob, &RSAKEK{pub: &priv.PublicKey, priv: priv})
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong private key, damaged file or changed header): %w", err)
	}
	dst := *out
	if dst == "" {
		dst = *in + ".dec"
	}
	if err := writeNew(dst, plain, *force); err != nil {
		return err
	}
	fmt.Printf("decrypted %s -> %s (%d bytes)\n  method=%s partner=%s class=%s original name=%s\n",
		*in, dst, len(plain), h.Alg, h.Partner, h.Classification, h.Filename)
	return nil
}

// ---------- WAY 2 commands: pre-shared key ----------

func loadMaster(list string) ([]byte, error) {
	var shares [][]byte
	for _, p := range strings.Split(list, ",") {
		b, err := os.ReadFile(strings.TrimSpace(p))
		if err != nil {
			return nil, err
		}
		s, err := b64.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if len(shares) > 0 && len(s) != len(shares[0]) {
			return nil, errors.New("shares have different lengths")
		}
		shares = append(shares, s)
	}
	if len(shares) < 2 {
		return nil, errors.New("-shares needs all share files, comma separated")
	}
	return xorCombine(shares), nil
}

func cmdPSKInit(args []string) error {
	fs := flag.NewFlagSet("psk-init", flag.ContinueOnError)
	partner := fs.String("partner", "", "partner id")
	dir := fs.String("dir", "keys", "folder for the share files")
	count := fs.Int("count", 3, "number of shares (2 to 10)")
	force := fs.Bool("force", false, "overwrite existing share files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *partner == "" {
		return errors.New("-partner is required")
	}
	if *count < 2 || *count > 10 {
		return errors.New("-count must be 2 to 10")
	}
	kek, err := getKEK() // Vault random if VAULT_ADDR is set, otherwise this computer's random
	if err != nil {
		return err
	}
	master, err := kek.Random(32)
	if err != nil {
		return err
	}
	p := filepath.Base(*partner)
	for i, s := range xorSplit(master, *count) {
		path := filepath.Join(*dir, fmt.Sprintf("psk-%s-share%d.txt", p, i+1))
		if err := writeNew(path, []byte(b64.EncodeToString(s)+"\n"), *force); err != nil {
			return err
		}
		fmt.Println("  wrote", path)
	}
	fmt.Printf("master key created by: %s\nGive each share to a DIFFERENT person and send them over DIFFERENT channels.\nAll %d shares are needed. Delete these files from this computer after delivery.\n",
		kek.Name(), *count)
	return nil
}

func cmdPSKEncrypt(args []string) error {
	fs := flag.NewFlagSet("psk-encrypt", flag.ContinueOnError)
	in := fs.String("in", "", "file to encrypt")
	partner := fs.String("partner", "", "partner id (bound into the file key)")
	shares := fs.String("shares", "", "all share files, comma separated")
	out := fs.String("out", "", "output file (default: <in>.psk)")
	force := fs.Bool("force", false, "overwrite output if it exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *partner == "" || *shares == "" {
		return errors.New("-in, -partner and -shares are required")
	}
	master, err := loadMaster(*shares)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	h, c, err := pskEncrypt(data, master, *partner, filepath.Base(*in))
	if err != nil {
		return err
	}
	dst := *out
	if dst == "" {
		dst = *in + ".psk"
	}
	if err := writeNew(dst, packMagic("PSK1", h, c), *force); err != nil {
		return err
	}
	fmt.Printf("encrypted %s -> %s (new random 32-byte salt -> new file key, salt stored in header)\n", *in, dst)
	return nil
}

func cmdPSKDecrypt(args []string) error {
	fs := flag.NewFlagSet("psk-decrypt", flag.ContinueOnError)
	in := fs.String("in", "", "encrypted file")
	shares := fs.String("shares", "", "all share files, comma separated")
	out := fs.String("out", "", "output file (default: <in>.dec)")
	force := fs.Bool("force", false, "overwrite output if it exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *shares == "" {
		return errors.New("-in and -shares are required")
	}
	master, err := loadMaster(*shares)
	if err != nil {
		return err
	}
	blob, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	h, c, err := unpackMagic("PSK1", blob)
	if err != nil {
		return err
	}
	plain, err := pskDecrypt(h, c, master)
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong or missing shares, or changed file): %w", err)
	}
	dst := *out
	if dst == "" {
		dst = *in + ".dec"
	}
	if err := writeNew(dst, plain, *force); err != nil {
		return err
	}
	fmt.Printf("decrypted %s -> %s (%d bytes)\n", *in, dst, len(plain))
	return nil
}
