"""Clip Sender: move text and files between this PC and our RDP server.

A text box, a Send button and a file picker. The RDP connection runs in the
background over a real, encrypted RDP session; no remote desktop window is ever
shown and no screen data is requested. Everything travels on the clipboard
channel (MS-RDPECLIP): text as CF_UNICODETEXT, files as a file group descriptor
plus streamed File Contents Responses.

It works in both directions. Anything the server offers - run
rdpclip_send.py there - arrives in the "From the server" pane, and files are
written into the received/ folder next to this script.

It talks to rdpclip_server.py, our own minimal RDP server, so none of the
workarounds a general-purpose RDP server would need are present here.

Usage:
  python clip_sender.py                      # open the window
  python clip_sender.py --send "text"        # send text once, from the shell
  python clip_sender.py --send-file PATH     # send a file once

Connection settings come from clip_sender.json next to this file.
"""
import asyncio
import json
import sys
import threading
from pathlib import Path
from urllib.parse import quote

from aardwolf.commons.factory import RDPConnectionFactory
from aardwolf.commons.iosettings import RDPIOSettings
from aardwolf.commons.queuedata import RDPDATATYPE

CONFIG_FILE = Path(__file__).with_name("clip_sender.json")
RECEIVED_DIR = Path(__file__).with_name("received")
DEFAULTS = {"host": "", "port": 3389, "user": "", "password": ""}


def load_config():
    cfg = dict(DEFAULTS)
    if CONFIG_FILE.exists():
        cfg.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
    return cfg


def save_config(cfg):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


async def connect_rdp(host, port, user, password):
    """Open an RDP session that is used only for its clipboard channel."""
    io = RDPIOSettings()
    # The smallest sane desktop. We never read a single pixel of it.
    io.video_width, io.video_height = 1024, 768
    io.clipboard_use_pyperclip = False  # don't touch this PC's own clipboard
    url = "rdp+plain://%s:%s@%s:%s" % (
        quote(str(user), safe=""), quote(str(password), safe=""), host, port)
    conn = RDPConnectionFactory.from_url(url, io).get_connection(io)
    _, err = await conn.connect()
    if err is not None:
        raise RuntimeError(str(err))
    RECEIVED_DIR.mkdir(exist_ok=True)
    conn.set_download_directory(str(RECEIVED_DIR))
    return conn


async def send_files(conn, paths):
    """Offer files to the server, which then pulls the bytes it wants."""
    # The clipboard keeps the paths it was last asked to share and indexes them
    # by position, but never clears them between copies - so without this the
    # server's file index would point at an earlier selection.
    conn.iosettings.clipboard._file_paths = []
    await conn.set_current_clipboard_files([Path(p) for p in paths])


async def receive_files(conn, report):
    """Download everything the server just offered into received/."""
    for index, descriptor in enumerate(conn.get_remote_file_list()):
        name = descriptor.fileName
        try:
            written = await conn.download_file(index)
        except Exception as exc:
            report("file %s failed: %s" % (name, exc))
            continue
        report("file received: %s (%d bytes) -> %s"
               % (name, written, RECEIVED_DIR / name))


class ClipLink:
    """A background RDP session that moves clipboard data both ways."""

    def __init__(self, on_status, on_incoming):
        self.on_status = on_status      # called from the worker thread
        self.on_incoming = on_incoming  # ditto, for data from the server
        self.loop = asyncio.new_event_loop()
        self.conn = None
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    # -- public API, callable from any thread

    def connect(self, host, port, user, password):
        return asyncio.run_coroutine_threadsafe(
            self._connect(host, port, user, password), self.loop)

    def send(self, text):
        return asyncio.run_coroutine_threadsafe(self._send(text), self.loop)

    def send_files(self, paths):
        return asyncio.run_coroutine_threadsafe(self._send_files(paths), self.loop)

    def close(self):
        fut = asyncio.run_coroutine_threadsafe(self._close(), self.loop)
        try:
            fut.result(timeout=5)
        except Exception:
            pass

    # -- coroutines running on the background loop

    async def _connect(self, host, port, user, password):
        await self._close()
        self.ready.clear()
        self.on_status("Connecting...")
        try:
            conn = await connect_rdp(host, port, user, password)
        except Exception as exc:
            self.on_status("Connection failed: %s" % exc)
            return False
        self.conn = conn
        asyncio.ensure_future(self._pump(conn))
        try:
            await asyncio.wait_for(self._wait_ready(), timeout=20)
        except asyncio.TimeoutError:
            self.on_status("Connected, but the clipboard channel never started")
            return False
        self.on_status("Connected - ready to send")
        return True

    async def _wait_ready(self):
        while not self.ready.is_set():
            await asyncio.sleep(0.05)

    async def _pump(self, conn):
        """Drain everything the server sends. There is no video to handle."""
        while True:
            item = await conn.ext_out_queue.get()
            if item is None:
                self.ready.clear()
                self.on_status("Disconnected")
                return
            if item.type == RDPDATATYPE.CLIPBOARD_READY:
                self.ready.set()
            elif item.type == RDPDATATYPE.CLIPBOARD_FORMAT_LIST_RESPONSE:
                self.on_status("Sent" if item.accepted else "Server rejected the data")
            elif item.type == RDPDATATYPE.CLIPBOARD_DATA_TXT:
                text = item.data
                if text:
                    self.on_incoming(str(text))
            elif item.type == RDPDATATYPE.CLIPBOARD_DATA_FILELIST:
                # Downloading blocks on the server's replies, so let it run on
                # its own and keep draining the queue.
                asyncio.ensure_future(receive_files(conn, self.on_incoming))

    async def _send(self, text):
        if self.conn is None or not self.ready.is_set():
            raise RuntimeError("not connected")
        await self.conn.set_current_clipboard_text(text)

    async def _send_files(self, paths):
        if self.conn is None or not self.ready.is_set():
            raise RuntimeError("not connected")
        await send_files(self.conn, paths)

    async def _close(self):
        if self.conn is not None:
            try:
                await self.conn.terminate()
            except Exception:
                pass
            self.conn = None
        self.ready.clear()


def run_cli(text=None, file_paths=None):
    """Send one string or one set of files and exit. Used for testing."""
    cfg = load_config()

    async def once():
        print("connecting to %s:%s ..." % (cfg["host"], cfg["port"]))
        conn = await connect_rdp(cfg["host"], cfg["port"], cfg["user"], cfg["password"])
        ready = asyncio.Event()

        async def pump():
            while True:
                item = await conn.ext_out_queue.get()
                if item is None:
                    return
                if item.type == RDPDATATYPE.CLIPBOARD_READY:
                    ready.set()

        task = asyncio.ensure_future(pump())
        await asyncio.wait_for(ready.wait(), timeout=20)
        if file_paths:
            print("sending files: %s" % ", ".join(file_paths))
            await send_files(conn, file_paths)
        else:
            print("sending: %s" % text)
            await conn.set_current_clipboard_text(text)
        # The server pulls the data on demand, so stay up while it does.
        await asyncio.sleep(10 if file_paths else 5)
        task.cancel()
        await conn.terminate()
        print("done")

    asyncio.run(once())


def run_gui():
    import tkinter as tk
    from tkinter import filedialog, ttk

    cfg = load_config()
    root = tk.Tk()
    root.title("Clip Sender")
    root.geometry("620x560")
    root.minsize(420, 420)

    status = tk.StringVar(value="Not connected")

    def show_incoming(line):
        def append():
            inbox.configure(state="normal")
            inbox.insert("end", line + "\n")
            inbox.see("end")
            inbox.configure(state="disabled")
        root.after(0, append)

    link = ClipLink(on_status=lambda s: root.after(0, status.set, s),
                    on_incoming=show_incoming)

    top = ttk.Frame(root, padding=8)
    top.pack(fill="x")
    fields = {}
    layout = [("host", "Server", 15), ("port", "Port", 6),
              ("user", "User", 10), ("password", "Password", 12)]
    for col, (key, label, width) in enumerate(layout):
        ttk.Label(top, text=label).grid(row=0, column=col, sticky="w", padx=2)
        var = tk.StringVar(value=str(cfg.get(key, "")))
        ttk.Entry(top, textvariable=var, width=width,
                  show="*" if key == "password" else "").grid(
                      row=1, column=col, padx=2, sticky="we")
        fields[key] = var

    def do_connect():
        try:
            port = int(fields["port"].get() or 3389)
        except ValueError:
            status.set("Port must be a number")
            return
        cfg.update({
            "host": fields["host"].get().strip(),
            "port": port,
            "user": fields["user"].get().strip(),
            "password": fields["password"].get(),
        })
        save_config(cfg)
        link.connect(cfg["host"], cfg["port"], cfg["user"], cfg["password"])

    ttk.Button(top, text="Connect", command=do_connect).grid(row=1, column=4, padx=(6, 0))

    ttk.Label(root, text="Text to send:", padding=(8, 4, 0, 0)).pack(anchor="w")
    box = tk.Text(root, wrap="word", height=8, font=("Segoe UI", 11), undo=True)
    box.pack(fill="both", expand=True, padx=8)

    bottom = ttk.Frame(root, padding=8)
    bottom.pack(fill="x")
    ttk.Label(bottom, textvariable=status).pack(side="left")

    def watch(fut, what):
        def done(f):
            exc = f.exception()
            if exc:
                root.after(0, status.set, "%s failed: %s" % (what, exc))
        fut.add_done_callback(done)

    def do_send(_event=None):
        text = box.get("1.0", "end-1c")
        if not text.strip():
            return "break"
        status.set("Sending...")
        watch(link.send(text), "Send")
        return "break"

    def do_send_files():
        paths = filedialog.askopenfilenames(title="Send to the server")
        if not paths:
            return
        status.set("Sending %d file(s)..." % len(paths))
        watch(link.send_files(list(paths)), "File send")

    ttk.Button(bottom, text="Send  (Ctrl+Enter)", command=do_send).pack(side="right")
    ttk.Button(bottom, text="Send file...", command=do_send_files).pack(
        side="right", padx=(0, 6))
    box.bind("<Control-Return>", do_send)

    ttk.Label(root, text="From the server:", padding=(8, 0, 0, 0)).pack(anchor="w")
    inbox = tk.Text(root, wrap="word", height=8, font=("Segoe UI", 10),
                    state="disabled")
    inbox.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    def on_close():
        link.close()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    if all(str(cfg.get(k, "")) for k in ("host", "user", "password")):
        root.after(200, do_connect)
    box.focus_set()
    root.mainloop()


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--send":
        run_cli(text=sys.argv[2])
    elif len(sys.argv) >= 3 and sys.argv[1] == "--send-file":
        run_cli(file_paths=sys.argv[2:])
    else:
        run_gui()
