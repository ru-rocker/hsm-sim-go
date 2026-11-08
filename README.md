# HSM simulation for "Encryption Standard" (Go) - with files on disk

* The "HSM" is **HashiCorp Vault Transit** in Docker. It holds the **KEK** and never gives it out.
* Vault now runs in **server mode with a saved volume**, so your encrypted files can still be opened after a restart.
* The program writes real files: a demo that saves every result in `./out`, and commands to encrypt/decrypt your own files.

| File | Job |
|---|---|
| `kek.go` | Talks to Vault (get DEK + wrapped DEK, unwrap, random, rotate) |
| `vaultinit.go` | First-time Vault setup + automatic unseal. Saves the keys to `vault-init.json` |
| `sym.go` | AES-256-GCM, ChaCha20-Poly1305, AES-256-CBC+HMAC |
| `asym.go` | OpenPGP (gpg), JWE + RSA-PSS, age |
| `sharing.go` | wrap DEK to partner, pre-shared key (HKDF + salt), passphrase (Argon2id/scrypt/PBKDF2 + salt) |
| `cli.go` | The commands: `demo`, `encrypt`, `decrypt`, `pass-encrypt`, `pass-decrypt` |
| `jwecmd.go` | JWE commands: `jwe-encrypt`, `jwe-decrypt` |
| `partner.go` | Commands for sharing with a partner: `keygen`, `wrap-encrypt`, `wrap-decrypt`, `psk-init`, `psk-encrypt`, `psk-decrypt` |
| `main.go` | The demo that runs every method and writes the results to `./out` |

---

## Step by step

### Step 0: What you need
* Go **1.24 or newer** (`go version`)
* Docker with Compose v2 (`docker compose version`)
* Optional: `gpg`, `age`, `age-keygen` on PATH. Without them, those two tests print `[SKIP]`.

### Step 1: Start Vault (the HSM)
In the project folder:
```
docker compose up -d vault
```
Vault starts **sealed and empty**. That is normal. The program prepares it for you in Step 3.

### Step 2: Tell the program where Vault is
macOS / Linux:
```
export VAULT_ADDR=http://localhost:8200
unset VAULT_TOKEN
```
Windows PowerShell:
```
$env:VAULT_ADDR="http://localhost:8200"
Remove-Item Env:VAULT_TOKEN -ErrorAction SilentlyContinue
```
`VAULT_TOKEN` must be **empty**. The program reads the real token from `vault-init.json`.

### Step 3: Download Go modules, then run the demo
```
go mod tidy
go run .
```
On this **first** run you will see:
```
Vault initialised. Unseal key + root token saved to vault-init.json (SIMULATION ONLY)
KEK provider: Vault Transit (docker)
=== 9.2 Symmetric file encryption ... ===
  [DISK] wrote out/sym-AES-256-GCM.enc (...)
  [OK]   AES-256-GCM: ... round-trip
...
All checks passed. Files written to ./out
```
What just happened: Vault was initialised and unsealed, the KEK `kek` was created inside Vault, and every method was tested.

### Step 4: Look at what was written to disk
```
ls out
```
| File | What it is | Can you decrypt it later? |
|---|---|---|
| `plain.csv` | the demo data | - |
| `sym-AES-256-GCM.enc` (+ `.dec`) | 9.2 encrypted file and the decrypted result | **Yes** (needs Vault) |
| `sym-CHACHA20-POLY1305.enc`, `sym-AES-256-CBC-HMAC.enc` | same, other methods | **Yes** (needs Vault) |
| `pass-argon2id.penc`, `pass-scrypt.penc`, `pass-pbkdf2.penc` | passphrase files | **Yes**, passphrase is `correct horse battery staple` |
| `pgp-rsa4096.pgp`, `jwe.jwe`, `age-style.age`, `psk.enc`, `partner-wrapped-dek.bin` | public-key / pre-shared examples | **No**. The demo makes throw-away keys and does not save them. |

The `.dec` files are the decrypted results. Check one:
```
diff out/plain.csv out/sym-AES-256-GCM.dec     # no output = identical
```
Open `out/sym-AES-256-GCM.enc` in a text editor: you will see unreadable data, with a readable header (the wrapped DEK is in there).

### Step 5: Encrypt and decrypt YOUR file (KEK + DEK, Vault)
Make a test file:
```
mkdir files
echo "hello secret" > files/hello.txt
```
Encrypt:
```
go run . encrypt -in files/hello.txt
```
This creates `files/hello.txt.enc`. Options: `-method gcm|chacha|cbc` (default gcm), `-partner partner-A`, `-class Restricted`, `-out somewhere.enc`, `-force`.

Decrypt:
```
go run . decrypt -in files/hello.txt.enc
```
This creates `files/hello.txt.enc.dec`. Check it:
```
cat files/hello.txt.enc.dec          # Windows: type files\hello.txt.enc.dec
```
You should see `hello secret`.

### Step 6: Prove the KEK survives a restart
```
docker compose restart vault
go run . decrypt -in files/hello.txt.enc -out files/again.txt
```
It says `Vault was sealed -> unsealed with the saved key`, then decrypts. The KEK lived on in Vault's volume.

### Step 7: Encrypt with a passphrase (salt)
macOS / Linux:
```
export HSM_PASSPHRASE='my long secret phrase'
go run . pass-encrypt -in files/hello.txt
go run . pass-decrypt -in files/hello.txt.penc -out files/hello_pass.txt
```
Windows PowerShell: use `$env:HSM_PASSPHRASE='my long secret phrase'`.
If you do not set it, the program asks for it (typing is visible). Choose the method with `-kdf argon2id|scrypt|pbkdf2`.
A new random **salt** is made for every file and stored in the file header. Encrypt the same file twice and compare the two `.penc` files: they are different.

### Step 8: OpenPGP and age on real files (no Go needed)
```
# age
age-keygen -o files/key.txt                      # prints "Public key: age1..."
age -r age1PASTE_YOUR_PUBLIC_KEY -o files/hello.age files/hello.txt
age -d -i files/key.txt -o files/hello_age.txt files/hello.age

# gpg
gpg --quick-generate-key me@example.com rsa4096 sign,cert never
gpg --quick-add-key <FINGERPRINT> rsa4096 encr never
gpg -r me@example.com --cipher-algo AES256 --digest-algo SHA256 --sign --encrypt -o files/hello.gpg files/hello.txt
gpg -o files/hello_gpg.txt --decrypt files/hello.gpg
```

### Step 9: Look inside Vault
```
docker exec hsm-sim-vault sh -c 'VAULT_ADDR=http://127.0.0.1:8200 vault status'
```
Or in a browser: http://localhost:8200, sign in with the `root_token` from `vault-init.json`.
You see the `transit` engine and a key named `kek`, but never its key material.

### Step 10: Stop or reset
| Goal | Command |
|---|---|
| Stop, **keep** keys and files decryptable | `docker compose down` |
| **Wipe everything** (all `.enc` files become undecryptable!) | `docker compose down -v` then delete `vault-init.json` |

### Optional: run the Go program inside Docker instead of locally
```
docker compose run --rm app hsmsim demo
docker compose run --rm app hsmsim encrypt -in files/hello.txt
```
It uses the same `vault-init.json`, `files/` and `out/` folders in your project (they are mounted as `/work`).

---

## Sharing with a partner: the 3 ways of section 9.3 (`sharing.go`)

Pick the **first** way your partner can handle. Setup for all of them: `mkdir files` and `echo "hello secret" > files/hello.txt`.
Your machine and the partner's machine are shown separately. On one computer, just run both parts yourself.

### WAY 1 (preferred): partner key pair, no secret is ever sent
**Partner's computer:**
```
go run . keygen -name partner
```
Creates `keys/partner_private.pem` (**never send**) and `keys/partner_public.pem` (safe to send). It prints a **fingerprint**. Read it to the bank by phone.
Send only `keys/partner_public.pem` to the bank.

**Bank's computer** (put the received file in `keys/`):
```
go run . wrap-encrypt -in files/hello.txt -pub keys/partner_public.pem -partner partner-A
```
Compare the fingerprint it prints with the one the partner read to you. If different, **stop**, the key is not the partner's.
This creates `files/hello.txt.wrap`. Send it to the partner. (Options: `-method gcm|chacha|cbc`, `-class Restricted`, `-out`, `-force`.)

**Partner's computer:**
```
go run . wrap-decrypt -in files/hello.txt.wrap -priv keys/partner_private.pem
```
Creates `files/hello.txt.wrap.dec`. Check it matches the original.

What happened: the file was locked with a random DEK, and the DEK was locked with the partner's public key. Only the private key opens it.

### WAY 2: pre-shared key (only if a shared secret is mandatory)
**Bank's computer, once per partner:**
```
go run . psk-init -partner partner-A
```
Creates three files: `keys/psk-partner-A-share1.txt`, `share2`, `share3`.
Give **each share to a different person** and deliver them over **different channels**. Delete the share files from this computer afterwards. If `VAULT_ADDR` is set, the master key comes from Vault's random generator.

**Encrypt (anyone holding all three shares):**
```
go run . psk-encrypt -in files/hello.txt -partner partner-A -shares keys/psk-partner-A-share1.txt,keys/psk-partner-A-share2.txt,keys/psk-partner-A-share3.txt
```
Creates `files/hello.txt.psk`. Every file gets a new random salt, so a new file key.

**Decrypt:**
```
go run . psk-decrypt -in files/hello.txt.psk -shares keys/psk-partner-A-share1.txt,keys/psk-partner-A-share2.txt,keys/psk-partner-A-share3.txt
```
Missing or wrong shares fail with `decrypt failed`. Rotate by running `psk-init` again every 6 to 12 months, or when a person leaves.

### WAY 3 (weakest, needs a signed risk acceptance): passphrase
```
export HSM_PASSPHRASE='a long passphrase'     # PowerShell: $env:HSM_PASSPHRASE='a long passphrase'
go run . pass-encrypt -in files/hello.txt
go run . pass-decrypt -in files/hello.txt.penc
```
Tell the partner the passphrase over a **separate** channel. Choose the method with `-kdf argon2id|scrypt|pbkdf2`.

**Important:** these file formats are this project's own. A partner cannot open them with `gpg` or `age`. They need this program (or code that follows the same format).

## JWE (section 9.1, pattern 2): for API payloads and small files

JWE = JSON Web Encryption. Format: `header.encrypted-key.iv.ciphertext.tag` (text, 5 parts). It uses RSA-OAEP-256 to lock a one-time key and AES-256-GCM to lock the data.
It is one single message in memory (no chunks), so use it for API payloads and small files, not huge ones.

**Partner's computer (once):**
```
go run . keygen -name partner
```
Send only `keys/partner_public.pem` to the bank, and read the fingerprint to the bank by phone.

**Bank's computer, encrypt only:**
```
go run . jwe-encrypt -in files/hello.txt -pub keys/partner_public.pem
```
Creates `files/hello.txt.jwe` (readable text). Check that the printed fingerprint matches what the partner read to you.

**Bank's computer, encrypt AND sign** (what section 8 asks for when you must prove who sent it):
```
go run . keygen -name bank
go run . jwe-encrypt -in files/hello.txt -pub keys/partner_public.pem -sign keys/bank_private.pem
```
Creates `files/hello.txt.jwe` and `files/hello.txt.jwe.sig`. Send both, plus `keys/bank_public.pem` (once).

**Partner's computer, decrypt:**
```
go run . jwe-decrypt -in files/hello.txt.jwe -priv keys/partner_private.pem
```
With signature check (do this when the file was signed):
```
go run . jwe-decrypt -in files/hello.txt.jwe -priv keys/partner_private.pem -verify keys/bank_public.pem
```
The signature is checked **first**. If it is not valid, the program stops and does not decrypt.

**Look inside** (macOS/Linux): the first part is the header in base64url:
```
cut -d. -f1 files/hello.txt.jwe | base64 -d
```
You should see `{"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"..."}`. (If `base64` complains about padding, the header is still printed.)

## What is a secret here (simulation only!)
* `vault-init.json` holds the unseal key and root token in **plain text**. Anyone with that file and the Vault volume has the KEK.
* In production: the unseal key is protected by a real HSM (or split among custodians), root tokens are not used, TLS is on, and audit logs go to the SIEM.
* The `keys/` folder holds **unprotected private keys and shares**. In production a partner's private key is kept in their HSM, and shares are never stored together.
* The demo's `out/` folder holds plaintext (`plain.csv`, `*.dec`). Delete it when done.

## Troubleshooting
| Problem | Fix |
|---|---|
| `permission denied` / `403` from Vault | You left `VAULT_TOKEN` set (e.g. to `root`). Unset it (Step 2). |
| `vault is already initialised but vault-init.json is missing` | You deleted the file but not the volume. Run `docker compose down -v`, then start again from Step 1. |
| `cannot reach Vault` | `docker compose ps` must show `vault` running. Check `VAULT_ADDR`. |
| `VAULT_ADDR is not set` when using `encrypt` | Do Step 2. Without Vault the key would exist only in memory. |
| `already exists (use -force ...)` | Add `-force` or pick another `-out`. |
| `decrypt failed` | Wrong Vault (it was reset), the file was changed, or the wrong passphrase. |
| `go: ... go.sum` / module errors | `go mod tidy` (needs internet). |
| Compile error | Send me the full error text. I could not compile this code when I wrote it. |
| gpg/age steps show `[SKIP]` | Install them (`brew install gnupg age`, `sudo apt install gnupg age`) and open a new terminal. |
