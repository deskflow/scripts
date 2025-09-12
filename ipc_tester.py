#!/usr/bin/env python3
import argparse, os, socket, sys


def main():
    ap = argparse.ArgumentParser(
        description="Send one line to Deskflow IPC and read one line back"
    )
    ap.add_argument("name", help="QLocalServer/pipe name")
    ap.add_argument("message", help="String to send")
    args = ap.parse_args()

    if os.name == "nt":
        path = r"\\.\pipe\{}".format(args.name)
        with open(path, "r+b", buffering=0) as f:
            f.write((args.message + "\n").encode())
            f.flush()
            reply = f.readline()
    else:
        path = os.path.join(os.environ.get("XDG_RUNTIME_DIR", "/tmp"), args.name)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(path)
        s.sendall((args.message + "\n").encode())
        reply = b""
        while not reply.endswith(b"\n"):
            chunk = s.recv(1)
            if not chunk:
                break
            reply += chunk
        s.close()

    sys.stdout.write(reply.decode(errors="replace"))


if __name__ == "__main__":
    main()
