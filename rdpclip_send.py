"""Send clipboard data from this server to the connected RDP client(s).

Talks to the control socket of a running rdpclip_server.py. The server then
announces the data on the clipboard channel and the client pulls it.

Usage:
  python3 rdpclip_send.py "some text"
  python3 rdpclip_send.py --file /etc/motd --file /root/pic.png
  python3 rdpclip_send.py --status
"""
import argparse
import json
import os
import socket
import sys

DEFAULT_SOCKET = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "control.sock")


def ask(sock_path, request):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(30)
        sock.connect(sock_path)
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    if not buf.strip():
        return {"ok": False, "error": "no answer from the server"}
    return json.loads(buf.decode("utf-8"))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("text", nargs="?", help="text to put on the client clipboard")
    ap.add_argument("--file", action="append", default=[], metavar="PATH",
                    help="send a file instead (repeatable)")
    ap.add_argument("--status", action="store_true", help="list connected clients")
    ap.add_argument("--socket", default=DEFAULT_SOCKET)
    args = ap.parse_args()

    if args.status:
        request = {"cmd": "status"}
    elif args.file:
        request = {"cmd": "file", "paths": [os.path.abspath(p) for p in args.file]}
    elif args.text:
        request = {"cmd": "text", "text": args.text}
    else:
        ap.error("give some text, --file or --status")

    try:
        answer = ask(args.socket, request)
    except (OSError, ValueError) as exc:
        print("control socket %s: %s" % (args.socket, exc), file=sys.stderr)
        return 2

    print(json.dumps(answer))
    return 0 if answer.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
