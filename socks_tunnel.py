"""A SOCKS5 proxy that tunnels through RDP, with the server as the exit.

Opens a POOL of RDP sessions to rdpclip_server.py (each its own TCP connection,
so transport is genuinely parallel, not time-sliced over one pipe) and runs one
local SOCKS5 listener. Each new browser connection is handed to the next
session round-robin, so one heavy stream only stalls others sharing its session
- and aggregate throughput scales with the pool size on a lossy or high-latency
link.

Usage:
  python socks_tunnel.py                 # SOCKS5 on 127.0.0.1:1080, 4 sessions
  python socks_tunnel.py 1090            # ... on a different port
  python socks_tunnel.py 1080 1          # ... single session (no pooling)

Verify the exit IP once it is up:
  curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
"""
import asyncio
import contextlib
import json
import logging
import sys
from pathlib import Path
from urllib.parse import quote

from aardwolf.commons.factory import RDPConnectionFactory
from aardwolf.commons.iosettings import RDPIOSettings

from rdp_tunnel_channel import RDPTunnelChannel, socks_handshake

CONFIG = Path(__file__).with_name("clip_sender.json")
DEFAULT_POOL = 4


async def drain_queue(conn):
    """Discard anything a connection emits; there is no video or clipboard."""
    while True:
        item = await conn.ext_out_queue.get()
        if item is None:
            return


async def open_session(cfg):
    """Bring up one RDP session and return (connection, tunnel channel)."""
    io = RDPIOSettings()
    io.video_width, io.video_height = 1024, 768
    io.clipboard_use_pyperclip = False
    io.channels = [RDPTunnelChannel]   # just our tunnel; no clipboard needed
    url = "rdp+plain://%s:%s@%s:%s" % (
        quote(cfg["user"], safe=""), quote(cfg["password"], safe=""),
        cfg["host"], cfg["port"])
    conn = RDPConnectionFactory.from_url(url, io).get_connection(io)
    _, err = await conn.connect()
    if err is not None:
        raise RuntimeError(str(err))
    # Exactly one channel is built per connection, so this is that channel.
    return conn, RDPTunnelChannel.latest_instance


class Frontend:
    """One SOCKS5 listener that spreads streams across the session pool."""

    def __init__(self, pool):
        self.pool = pool
        self._next = 0

    async def handle(self, reader, writer):
        try:
            target = await socks_handshake(reader, writer)
        except Exception:
            target = None
        if target is None:
            with contextlib.suppress(Exception):
                writer.close()
            return
        channel = self.pool[self._next % len(self.pool)]
        self._next += 1
        await channel.carry(reader, writer, *target)


async def main(port, pool_size):
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s")
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))

    conns, channels, drainers = [], [], []
    print("opening %d session(s) to %s:%s ..." % (pool_size, cfg["host"], cfg["port"]),
          flush=True)
    for i in range(pool_size):
        try:
            conn, channel = await open_session(cfg)
        except Exception as exc:
            print("session %d failed: %s" % (i + 1, exc), flush=True)
            if not channels:
                return 1  # could not open even one
            break
        conns.append(conn)
        channels.append(channel)
        drainers.append(asyncio.ensure_future(drain_queue(conn)))
        print("session %d up" % (i + 1), flush=True)

    frontend = Frontend(channels)
    server = await asyncio.start_server(frontend.handle, "127.0.0.1", port)
    print("ready: %d parallel session(s); set your browser SOCKS5 to 127.0.0.1:%d"
          % (len(channels), port), flush=True)
    print("test:  curl --socks5-hostname 127.0.0.1:%d https://ifconfig.me" % port,
          flush=True)
    try:
        async with server:
            await server.serve_forever()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        for drainer in drainers:
            drainer.cancel()
        for channel in channels:
            await channel.shutdown()
        for conn in conns:
            with contextlib.suppress(Exception):
                await conn.terminate()
    return 0


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 1080
    pool_size = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_POOL
    try:
        sys.exit(asyncio.run(main(port, max(1, pool_size))))
    except KeyboardInterrupt:
        pass
