package main

// Command line: real files on disk.
//   go run . demo                          run all tests, write every result into ./out
//   go run . encrypt      -in F [-method gcm|chacha|cbc] [-partner P] [-class C] [-out F.enc]   (KEK/DEK via Vault)
//   go run . decrypt      -in F.enc [-out F.dec]
//   go run . pass-encrypt -in F [-kdf argon2id|scrypt|pbkdf2] [-out F.penc]                     (passphrase + salt)
//   go run . pass-decrypt -in F.penc [-out F.dec]

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func usage() {
	fmt.Println(`usage: go run . <command> [flags]

  demo           run every test, write all results into ./out   (default)
  encrypt        encrypt a file with a Vault-wrapped DEK   -in F [-method gcm|chacha|cbc] [-partner P] [-class C] [-out F] [-force]
  decrypt        decrypt a file made by 'encrypt'          -in F [-out F] [-force]
  pass-encrypt   encrypt a file with a passphrase + salt   -in F [-kdf argon2id|scrypt|pbkdf2] [-out F] [-force]
  pass-decrypt   decrypt a file made by 'pass-encrypt'     -in F [-out F] [-force]

  keygen         WAY 1: make a partner RSA key pair        [-name N] [-dir keys] [-bits 3072|4096]
  wrap-encrypt   WAY 1: encrypt for a partner public key   -in F -pub PUBLIC.pem [-partner P] [-class C] [-method gcm|chacha|cbc]
  wrap-decrypt   WAY 1: decrypt with your private key      -in F -priv PRIVATE.pem [-out F]
  jwe-encrypt    JWE: encrypt for a partner public key     -in F -pub PUBLIC.pem [-sign YOUR_PRIVATE.pem] [-kid K] [-out F]
  jwe-decrypt    JWE: decrypt with your private key        -in F -priv PRIVATE.pem [-verify SENDER_PUBLIC.pem] [-out F]
  psk-init       WAY 2: make master key, split into shares -partner P [-count 3] [-dir keys]
  psk-encrypt    WAY 2: encrypt with the shared master key -in F -partner P -shares s1,s2,s3
  psk-decrypt    WAY 2: decrypt with the shared master key -in F -shares s1,s2,s3

passphrase: set HSM_PASSPHRASE, or you will be asked (typing is visible).`)
}

func main() {
	cmd, args := "demo", []string{}
	if len(os.Args) > 1 {
		cmd, args = os.Args[1], os.Args[2:]
	}
	var err error
	switch cmd {
	case "demo":
		err = runDemo()
	case "encrypt":
		err = cmdEncrypt(args)
	case "decrypt":
		err = cmdDecrypt(args)
	case "pass-encrypt":
		err = cmdPassEncrypt(args)
	case "pass-decrypt":
		err = cmdPassDecrypt(args)
	case "jwe-encrypt":
		err = cmdJWEEncrypt(args)
	case "jwe-decrypt":
		err = cmdJWEDecrypt(args)
	case "keygen":
		err = cmdKeygen(args)
	case "wrap-encrypt":
		err = cmdWrapEncrypt(args)
	case "wrap-decrypt":
		err = cmdWrapDecrypt(args)
	case "psk-init":
		err = cmdPSKInit(args)
	case "psk-encrypt":
		err = cmdPSKEncrypt(args)
	case "psk-decrypt":
		err = cmdPSKDecrypt(args)
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// ---------- helpers ----------

func writeNew(path string, data []byte, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists (use -force to overwrite)", path)
		}
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o600)
}

func algFromName(n string) (string, error) {
	switch strings.ToLower(n) {
	case "gcm":
		return AlgGCM, nil
	case "chacha":
		return AlgChaCha, nil
	case "cbc":
		return AlgCBC, nil
	}
	return "", fmt.Errorf("unknown method %q (use gcm, chacha or cbc)", n)
}

func requireVault() (KEK, error) {
	k, err := getKEK()
	if err != nil {
		return nil, err
	}
	if _, soft := k.(*SoftKEK); soft {
		return nil, errors.New("VAULT_ADDR is not set. SoftKEK lives only in memory, so a file encrypted with it could never be decrypted later")
	}
	return k, nil
}

func readPassphrase() (string, error) {
	if p := os.Getenv("HSM_PASSPHRASE"); p != "" {
		return p, nil
	}
	fmt.Fprint(os.Stderr, "Passphrase (typing is visible): ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	p := strings.TrimRight(line, "\r\n")
	if p == "" {
		return "", errors.New("empty passphrase")
	}
	return p, nil
}

// container used by pass-encrypt and psk-encrypt: MAGIC | uint32 len(header) | header(JSON) | ciphertext
func packMagic(magic string, h, c []byte) []byte {
	var b bytes.Buffer
	b.WriteString(magic)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(h)))
	b.Write(l[:])
	b.Write(h)
	b.Write(c)
	return b.Bytes()
}

func unpackMagic(magic string, blob []byte) (h, c []byte, err error) {
	n := len(magic)
	if len(blob) < n+4 || string(blob[:n]) != magic {
		return nil, nil, fmt.Errorf("bad magic (this is not a %s file)", magic)
	}
	hl := int(binary.BigEndian.Uint32(blob[n : n+4]))
	if hl < 0 || n+4+hl > len(blob) {
		return nil, nil, errors.New("bad header length")
	}
	return blob[n+4 : n+4+hl], blob[n+4+hl:], nil
}

func packPass(h, c []byte) []byte { return packMagic("PASS1", h, c) }

func unpackPass(blob []byte) ([]byte, []byte, error) { return unpackMagic("PASS1", blob) }

// ---------- commands ----------

func cmdEncrypt(args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	method := fs.String("method", "gcm", "gcm | chacha | cbc")
	in := fs.String("in", "", "file to encrypt")
	out := fs.String("out", "", "output file (default: <in>.enc)")
	partner := fs.String("partner", "partner-A", "partner id (bound into the wrapped key)")
	class := fs.String("class", "Restricted", "classification (bound into the wrapped key)")
	force := fs.Bool("force", false, "overwrite output if it exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return errors.New("-in is required")
	}
	alg, err := algFromName(*method)
	if err != nil {
		return err
	}
	kek, err := requireVault()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	meta := Meta{Filename: filepath.Base(*in), Classification: *class, Partner: *partner}
	blob, err := Encrypt(data, kek, alg, meta, 64*1024)
	if err != nil {
		return err
	}
	dst := *out
	if dst == "" {
		dst = *in + ".enc"
	}
	if err := writeNew(dst, blob, *force); err != nil {
		return err
	}
	fmt.Printf("encrypted %s (%d bytes) -> %s (%d bytes)\n  method=%s partner=%s class=%s\n  DEK wrapped by KEK in %s\n",
		*in, len(data), dst, len(blob), alg, *partner, *class, kek.Name())
	return nil
}

func cmdDecrypt(args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	in := fs.String("in", "", "encrypted file")
	out := fs.String("out", "", "output file (default: <in>.dec)")
	force := fs.Bool("force", false, "overwrite output if it exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return errors.New("-in is required")
	}
	kek, err := requireVault()
	if err != nil {
		return err
	}
	blob, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	plain, h, err := Decrypt(blob, kek)
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong Vault, damaged file or changed header): %w", err)
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

func cmdPassEncrypt(args []string) error {
	fs := flag.NewFlagSet("pass-encrypt", flag.ContinueOnError)
	kdfName := fs.String("kdf", "argon2id", "argon2id | scrypt | pbkdf2")
	in := fs.String("in", "", "file to encrypt")
	out := fs.String("out", "", "output file (default: <in>.penc)")
	force := fs.Bool("force", false, "overwrite output if it exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return errors.New("-in is required")
	}
	pass, err := readPassphrase()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	h, c, err := passphraseEncrypt(data, pass, *kdfName)
	if err != nil {
		return err
	}
	dst := *out
	if dst == "" {
		dst = *in + ".penc"
	}
	if err := writeNew(dst, packPass(h, c), *force); err != nil {
		return err
	}
	fmt.Printf("encrypted %s -> %s (kdf=%s, random 16-byte salt stored in the file header)\n", *in, dst, *kdfName)
	return nil
}

func cmdPassDecrypt(args []string) error {
	fs := flag.NewFlagSet("pass-decrypt", flag.ContinueOnError)
	in := fs.String("in", "", "encrypted file")
	out := fs.String("out", "", "output file (default: <in>.dec)")
	force := fs.Bool("force", false, "overwrite output if it exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return errors.New("-in is required")
	}
	pass, err := readPassphrase()
	if err != nil {
		return err
	}
	blob, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	h, c, err := unpackPass(blob)
	if err != nil {
		return err
	}
	plain, err := passphraseDecrypt(h, c, pass)
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong passphrase or damaged file): %w", err)
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
