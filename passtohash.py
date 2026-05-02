#!/usr/bin/env python3
"""
passtohash.py — Derive Kerberos AES keys and NTLM hash from:
  - a bloodyAD B64ENCODED gMSA blob  (-b64)
  - a cleartext password             (-p)

Usage:
    python3 passtohash.py -b64 <B64_BLOB>   -a <sAMAccountName> -d <domain> [options]
    python3 passtohash.py -p   <cleartext>  -a <sAMAccountName> -d <domain> [options]

Examples:
    # gMSA blob from bloodyAD
    python3 passtohash.py -b64 'eFkb...' -a 'LOCAL_gMSA$' -d 'local.htb'

    # Cleartext — machine account ($ suffix → host salt)
    python3 passtohash.py -p 'S3cr3tP@ss!' -a 'machine1$' -d 'local.htb'

    # Cleartext — user account (no $ → user salt)
    python3 passtohash.py -p 'S3cr3tP@ss!' -a 'jdoe' -d 'local.htb'

    # Read blob from file
    python3 passtohash.py -b64 --file blob.txt -a 'LOCAL_gMSA$' -d 'local.htb'

    # Bare output for piping into hashcat / secretsdump
    python3 passtohash.py -b64 'eFkb...' -a 'LOCAL_gMSA$' -d 'local.htb' --hashcat

    # Verbose — raw hex, byte lengths, blob size
    python3 passtohash.py -b64 'eFkb...' -a 'LOCAL_gMSA$' -d 'local.htb' --verbose

Salt logic (auto-detected from sAMAccountName):
    Machine account (ends in $): DOMAIN.UPPERhostaccount.domain.lower
    User account (no $):         DOMAIN.UPPERusername

Dependencies:
    pip install impacket
"""

import sys
import argparse
import base64
import struct
from binascii import hexlify

try:
    from impacket.krb5 import constants
    from impacket.krb5.crypto import string_to_key
except ImportError:
    print("[!] impacket not found. Install with: pip install impacket", file=sys.stderr)
    sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# Blob parsing
# ──────────────────────────────────────────────────────────────────────────────

def parse_msds_managed_password(raw: bytes) -> bytes:
    """
    Parse MSDS-MANAGEDPASSWORD_BLOB (MS-ADTS §2.2.37) and return the
    CurrentPassword field as raw UTF-16LE bytes.

    Structure:
        Offset  Size  Field
        0       2     Version (must be 0x0001)
        2       2     Reserved
        4       4     Length (total blob)
        8       2     CurrentPasswordOffset
        10      2     PreviousPasswordOffset (0 = no previous)
        12      2     QueryPasswordIntervalOffset
        14      2     UnchangedPasswordIntervalOffset
        16+           Password data

    Falls back to treating the entire blob as the password if Version != 1
    (some tools dump only the password portion without the header).
    """
    if len(raw) < 16:
        raise ValueError("Blob too short to be a valid MSDS-MANAGEDPASSWORD_BLOB")

    version = struct.unpack_from("<H", raw, 0)[0]
    if version != 1:
        return raw  # raw password bytes, no header

    current_offset  = struct.unpack_from("<H", raw, 8)[0]
    previous_offset = struct.unpack_from("<H", raw, 10)[0]
    query_offset    = struct.unpack_from("<H", raw, 12)[0]

    # Upper bound: next non-zero offset after CurrentPassword, or end of blob
    upper = next((o for o in (previous_offset, query_offset) if o > 0), len(raw))
    return raw[current_offset:upper]


# ──────────────────────────────────────────────────────────────────────────────
# Crypto helpers
# ──────────────────────────────────────────────────────────────────────────────

def build_salt(domain: str, sam: str) -> str:
    """
    Kerberos salt — auto-detected from sAMAccountName:

    Machine account (ends in $):
        <DOMAIN_UPPER>host<account_lower_no_dollar>.<domain_lower>
        e.g. LOCAL.HTBhostmachine1.local.htb

    User account (no $):
        <DOMAIN_UPPER><username_lower>
        e.g. LOCAL.HTBjdoe
    """
    domain_upper = domain.upper()
    domain_lower = domain.lower()

    if sam.endswith("$"):
        account = sam.rstrip("$").lower()
        return f"{domain_upper}host{account}.{domain_lower}"
    else:
        return f"{domain_upper}{sam.lower()}"


def nt_hash(pwd_utf16le: bytes) -> str:
    """Compute NTLM hash (MD4 of UTF-16LE password bytes)."""
    import hashlib
    try:
        return hashlib.new("md4", pwd_utf16le).hexdigest()
    except ValueError:
        pass
    try:
        from Crypto.Hash import MD4
        return MD4.new(pwd_utf16le).hexdigest()
    except ImportError:
        pass
    return _md4_pure(pwd_utf16le)


def _md4_pure(data: bytes) -> str:
    """Pure-Python MD4 (RFC 1320) — fallback for OpenSSL 3 systems."""
    import struct as _s

    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z
    def rol(x, n):  return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    msg = bytearray(data)
    orig_len_bits = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += _s.pack("<Q", orig_len_bits)

    A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for i in range(0, len(msg), 64):
        X = list(_s.unpack_from("<16I", msg, i))
        a, b, c, d = A, B, C, D

        for k in range(16):
            a = rol((a + F(b, c, d) + X[k]) & 0xFFFFFFFF, [3,7,11,19][k % 4])
            a, b, c, d = d, a, b, c

        for k in [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]:
            a = rol((a + G(b, c, d) + X[k] + 0x5A827999) & 0xFFFFFFFF, [3,5,9,13][k % 4])
            a, b, c, d = d, a, b, c

        for k in [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]:
            a = rol((a + H(b, c, d) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, [3,9,11,15][k % 4])
            a, b, c, d = d, a, b, c

        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF

    return _s.pack("<4I", A, B, C, D).hex()


def derive_aes(pwd_utf8: bytes, salt: str) -> tuple[str, str]:
    """Return (aes256_hex, aes128_hex) from UTF-8 password bytes and salt string."""
    aes256 = hexlify(
        string_to_key(
            constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
            pwd_utf8, salt
        ).contents
    ).decode()

    aes128 = hexlify(
        string_to_key(
            constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
            pwd_utf8, salt
        ).contents
    ).decode()

    return aes256, aes128


# ──────────────────────────────────────────────────────────────────────────────
# Input modes
# ──────────────────────────────────────────────────────────────────────────────

def load_blob(b64_value: str, from_file: bool) -> tuple[bytes, bytes, bytes]:
    """
    Load and parse a gMSA blob.

    Returns (pwd_utf16le, pwd_utf8, raw_blob) where:
        pwd_utf16le  — raw CurrentPassword bytes for NTLM derivation
        pwd_utf8     — re-encoded UTF-8 for impacket string_to_key
        raw_blob     — original decoded blob (for verbose reporting)
    """
    if from_file:
        with open(b64_value, "r") as fh:
            b64_data = fh.read().strip()
    else:
        b64_data = b64_value.strip()

    try:
        raw = base64.b64decode(b64_data)
    except Exception as e:
        print(f"[!] Base64 decode failed: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        pwd_utf16le = parse_msds_managed_password(raw)
    except ValueError as e:
        print(f"[!] Blob parse error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        pwd_str = pwd_utf16le.decode("utf-16-le", errors="replace")
    except Exception as e:
        print(f"[!] UTF-16LE decode error: {e}", file=sys.stderr)
        sys.exit(1)

    return pwd_utf16le, pwd_str.encode("utf-8"), raw


def load_cleartext(password: str) -> tuple[bytes, bytes]:
    """
    Encode a cleartext password into (pwd_utf16le, pwd_utf8).

    pwd_utf16le  — for NTLM derivation
    pwd_utf8     — for impacket string_to_key (Kerberos AES)
    """
    return password.encode("utf-16-le"), password.encode("utf-8")


# ──────────────────────────────────────────────────────────────────────────────
# Output
# ──────────────────────────────────────────────────────────────────────────────

def print_results(sam: str, salt: str, ntlm: str, aes256: str, aes128: str,
                  hashcat: bool, verbose: bool,
                  pwd_utf16le: bytes = b"", pwd_utf8: bytes = b"",
                  raw_blob: bytes = b""):
    if hashcat:
        print(f"{sam}:{ntlm}")
        print(f"{sam}:aes256-cts-hmac-sha1-96:{aes256}")
        print(f"{sam}:aes128-cts-hmac-sha1-96:{aes128}")
        return

    print(f"\n[*] Salt      : {salt}")
    print(f"[*] NTLM      : {ntlm}")

    if verbose and pwd_utf16le:
        print(f"[*] Pwd hex   : {hexlify(pwd_utf16le).decode()}")
        print(f"[*] Pwd len   : {len(pwd_utf16le)} bytes (UTF-16LE) / "
              f"{len(pwd_utf8)} bytes (UTF-8)")
        if raw_blob:
            print(f"[*] Blob len  : {len(raw_blob)} bytes")

    print()
    print(f"{sam}:aes256-cts-hmac-sha1-96:{aes256}")
    print(f"{sam}:aes128-cts-hmac-sha1-96:{aes128}")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="passtohash.py",
        description="Derive Kerberos AES keys and NTLM hash from a gMSA blob or cleartext password.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # ── Input source (mutually exclusive) ─────────────────────────────────────
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "-b64", metavar="B64_BLOB",
        help="Base64-encoded msDS-ManagedPassword blob from bloodyAD "
             "(use '-b64 --file PATH' to read from file)",
    )
    src.add_argument(
        "-p", metavar="CLEARTEXT",
        help="Cleartext password string",
    )
    src.add_argument(
        "-pfile", metavar="PATH",
        help="Read cleartext password from file (avoids shell expansion of special chars)",
    )

    # ── Account / domain ──────────────────────────────────────────────────────
    parser.add_argument(
        "-a", required=True, metavar="sAMAccountName",
        help="Account name — include $ for machine/gMSA accounts (e.g. machine1$, LOCAL_gMSA$)",
    )
    parser.add_argument(
        "-d", required=True, metavar="domain",
        help="FQDN of the domain (e.g. local.htb)",
    )

    # ── Blob options ──────────────────────────────────────────────────────────
    parser.add_argument(
        "--file", "-f", action="store_true",
        help="Treat the -b64 value as a file path rather than a literal blob string",
    )

    # ── Output options ────────────────────────────────────────────────────────
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print raw password hex, byte lengths, and blob size",
    )
    parser.add_argument(
        "--hashcat", action="store_true",
        help="Bare output — no decoration; suitable for piping into hashcat/john",
    )

    args = parser.parse_args()

    # ── Resolve input ─────────────────────────────────────────────────────────
    raw_blob = b""

    if args.b64 is not None:
        if args.file:
            pwd_utf16le, pwd_utf8, raw_blob = load_blob(args.b64, from_file=True)
        else:
            pwd_utf16le, pwd_utf8, raw_blob = load_blob(args.b64, from_file=False)
    elif args.pfile is not None:
        try:
            with open(args.pfile, "r") as fh:
                password = fh.read().rstrip("\n")
        except OSError as e:
            print(f"[!] Cannot read file: {e}", file=sys.stderr)
            sys.exit(1)
        pwd_utf16le, pwd_utf8 = load_cleartext(password)
    else:
        # -p cleartext mode — --file flag is irrelevant here
        if args.file:
            parser.error("--file only applies to -b64 mode; use -pfile PATH for cleartext from file")
        pwd_utf16le, pwd_utf8 = load_cleartext(args.p)

    # ── Derive ────────────────────────────────────────────────────────────────
    salt            = build_salt(args.d, args.a)
    ntlm            = nt_hash(pwd_utf16le)
    aes256, aes128  = derive_aes(pwd_utf8, salt)

    # ── Print ─────────────────────────────────────────────────────────────────
    print_results(
        sam=args.a, salt=salt, ntlm=ntlm,
        aes256=aes256, aes128=aes128,
        hashcat=args.hashcat, verbose=args.verbose,
        pwd_utf16le=pwd_utf16le, pwd_utf8=pwd_utf8, raw_blob=raw_blob,
    )


if __name__ == "__main__":
    main()
