package main

// Section 9.1 pattern 2 on real files: JWE (RSA-OAEP-256 + A256GCM), optional RSA-PSS signature.
//   go run . keygen -name partner                                   (partner: makes the key pair)
//   go run . keygen -name bank                                      (sender, only if you want to sign)
//   go run . jwe-encrypt -in F -pub keys/partner_public.pem [-sign keys/bank_private.pem]
//   go run . jwe-decrypt -in F.jwe -priv keys/partner_private.pem [-verify keys/bank_public.pem]

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

func cmdJWEEncrypt(args []string) error {
	fs := flag.NewFlagSet("jwe-encrypt", flag.ContinueOnError)
	in := fs.String("in", "", "file to encrypt")
	pubPath := fs.String("pub", "", "partner public key (PEM)")
	out := fs.String("out", "", "output file (default: <in>.jwe)")
	kid := fs.String("kid", "", "key id written into the JWE header (default: start of the key fingerprint)")
	signPath := fs.String("sign", "", "optional: YOUR private key (PEM); writes <out>.sig, an RSA-PSS signature")
	force := fs.Bool("force", false, "overwrite output if it exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *pubPath == "" {
		return errors.New("-in and -pub are required")
	}
	pub, err := loadPub(*pubPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	k := *kid
	if k == "" {
		k = pubFingerprint(pub)[:16]
	}
	tok, err := jweEncrypt(pub, data, k)
	if err != nil {
		return err
	}
	dst := *out
	if dst == "" {
		dst = *in + ".jwe"
	}
	if err := writeNew(dst, []byte(tok), *force); err != nil {
		return err
	}
	fmt.Printf("encrypted %s (%d bytes) -> %s (%d chars of text)\n  alg=RSA-OAEP-256 (wraps the key)  enc=A256GCM (locks the data)  kid=%s\n  Partner key fingerprint: %s\n  (make sure this matches what the partner told you)\n",
		*in, len(data), dst, len(tok), k, spaced(pubFingerprint(pub)))
	if *signPath != "" {
		priv, err := loadPriv(*signPath)
		if err != nil {
			return err
		}
		sig, err := pssSign(priv, []byte(tok))
		if err != nil {
			return err
		}
		if err := writeNew(dst+".sig", sig, *force); err != nil {
			return err
		}
		fmt.Printf("signed with RSA-PSS (SHA-256) -> %s.sig\n  Send BOTH files: %s and %s.sig\n", dst, dst, dst)
	}
	return nil
}

func cmdJWEDecrypt(args []string) error {
	fs := flag.NewFlagSet("jwe-decrypt", flag.ContinueOnError)
	in := fs.String("in", "", "JWE file")
	privPath := fs.String("priv", "", "your private key (PEM)")
	verifyPath := fs.String("verify", "", "optional: sender public key (PEM); checks <in>.sig before decrypting")
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
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	tok := strings.TrimSpace(string(raw))
	if *verifyPath != "" { // check who sent it BEFORE trusting anything
		spub, err := loadPub(*verifyPath)
		if err != nil {
			return err
		}
		sig, err := os.ReadFile(*in + ".sig")
		if err != nil {
			return fmt.Errorf("cannot read signature file: %w", err)
		}
		if err := pssVerify(spub, []byte(tok), sig); err != nil {
			return fmt.Errorf("SIGNATURE NOT VALID, do not trust this file: %w", err)
		}
		fmt.Println("signature OK: the file is unchanged and was signed by the owner of that key")
	}
	plain, err := jweDecrypt(priv, tok)
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong private key or changed file): %w", err)
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
