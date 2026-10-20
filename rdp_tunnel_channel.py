"""A custom RDP static virtual channel that carries TCP streams.

This is the transport half of our SOCKS-over-RDP tunnel. It plugs into aardwolf
as an ordinary channel (add the class to iosettings.channels). Each channel is
one RDP session's mux pipe; TCP streams are multiplexed over it with a tiny
protocol:

    stream_id (u32) . opcode (u8) . payload

one virtual-channel message (FIRST..LAST fragments) per frame. The SOCKS5 front
end and the pooling across several sessions live in socks_tunnel.py - this file
just moves bytes for one session.

This is essentially what rdp2tcp's SOCKS mode does, but over a channel we own
rather than Microsoft's, so it needs no agent binary or client DLL.
"""
import asyncio
import contextlib
import logging
import socket
import struct

from aardwolf.channels import Channel
from aardwolf.protocol.T124.userdata.constants import ChannelOption
from aardwolf.protocol.channelpdu import CHANNEL_PDU_HEADER, CHANNEL_FLAG

logger = logging.getLogger("rdptun")

TUN_OPEN = 1
TUN_OK = 2
TUN_FAIL = 3
TUN_DATA = 4
TUN_CLOSE = 5

VC_CHUNK_SIZE = 1600   # must not exceed the server's advertised VCChunkSize
# How much we read from a browser socket per frame. The send lock is held for
# one whole frame, so a smaller value lets a session's streams interleave more
# finely and cuts head-of-line stalls. Two VC chunks balances latency against
# the small per-frame overhead; throughput is unchanged (the VC chunk is).
BROWSER_READ_CHUNK = 3200


async def socks_handshake(reader, writer):
    """Minimal SOCKS5, CONNECT only. Returns (host, port) or None."""
    if await reader.readexactly(1) != b"\x05":
        return None  # we only speak SOCKS5
    nmethods = (await reader.readexactly(1))[0]
    await reader.readexactly(nmethods)
    writer.write(b"\x05\x00")  # no authentication
    await writer.drain()

    header = await reader.readexactly(4)
    if header[0] != 0x05:
        return None
    cmd, atyp = header[1], header[3]
    if atyp == 0x01:
        host = socket.inet_ntoa(await reader.readexactly(4))
    elif atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(length)).decode("utf-8", "replace")
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    else:
        return None
    port = struct.unpack(">H", await reader.readexactly(2))[0]

    if cmd != 0x01:  # only CONNECT; no BIND or UDP ASSOCIATE
        writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()
        return None
    return host, port


class RDPTunnelChannel(Channel):
    """One static virtual channel multiplexing many TCP streams."""

    name = "rdptun"
    # The connection deep-copies iosettings before building channels, so we
    # cannot hand the instance back through iosettings. The runner picks up the
    # last channel constructed in this process after each connect().
    latest_instance = None

    def __init__(self, iosettings):
        Channel.__init__(self, self.name,
                         ChannelOption.INITIALIZED | ChannelOption.ENCRYPT_RDP
                         | ChannelOption.COMPRESS_RDP | ChannelOption.SHOW_PROTOCOL)
        self.iosettings = iosettings
        self._buffer = b""           # inbound reassembly
        self._streams = {}           # stream id -> browser-side StreamWriter
        self._tasks = {}             # stream id -> browser read task
        self._open_waiters = {}      # stream id -> Future(bool) for OPEN result
        self._next_id = 1
        self._send_lock = asyncio.Lock()
        RDPTunnelChannel.latest_instance = self

    # -- channel lifecycle

    async def start(self):
        return True, None

    async def stop(self):
        await self.shutdown()
        return True, None

    async def shutdown(self):
        for task in list(self._tasks.values()):
            task.cancel()
        for writer in list(self._streams.values()):
            with contextlib.suppress(Exception):
                writer.close()
        self._streams.clear()
        self._tasks.clear()

    # -- carrying one browser connection (called by the SOCKS front end)

    async def carry(self, reader, writer, host, port):
        """Open a stream for an already-handshaken browser connection."""
        stream_id = self._next_id
        self._next_id += 1

        waiter = asyncio.get_event_loop().create_future()
        self._open_waiters[stream_id] = waiter
        await self._send_frame(stream_id, TUN_OPEN,
                               struct.pack("<H", port) + host.encode("utf-8"))
        try:
            ok = await asyncio.wait_for(waiter, timeout=20)
        except asyncio.TimeoutError:
            ok = False
        finally:
            self._open_waiters.pop(stream_id, None)

        # SOCKS5 reply: 0x00 success, 0x05 refused. BND addr is ignored by
        # clients for CONNECT, so we send an all-zero IPv4.
        reply = b"\x05" + (b"\x00" if ok else b"\x05") + b"\x00\x01" \
            + b"\x00\x00\x00\x00" + b"\x00\x00"
        writer.write(reply)
        await writer.drain()
        if not ok:
            with contextlib.suppress(Exception):
                writer.close()
            return

        self._streams[stream_id] = writer
        logger.info("tunnel %d open -> %s:%d", stream_id, host, port)
        self._tasks[stream_id] = asyncio.ensure_future(
            self._pump_browser(stream_id, reader))

    # -- sending frames on the channel

    async def _send_frame(self, stream_id, opcode, payload=b""):
        msg = struct.pack("<IB", stream_id, opcode) + payload
        total = len(msg)
        async with self._send_lock:
            offset = 0
            while True:
                chunk = msg[offset:offset + VC_CHUNK_SIZE]
                flags = CHANNEL_FLAG.CHANNEL_FLAG_SHOW_PROTOCOL
                if offset == 0:
                    flags |= CHANNEL_FLAG.CHANNEL_FLAG_FIRST
                offset += len(chunk)
                if offset >= total:
                    flags |= CHANNEL_FLAG.CHANNEL_FLAG_LAST
                packet = CHANNEL_PDU_HEADER.serialize_packet(flags, chunk, length=total)
                await self.send_channel_data(packet, None, None, None, False)
                if flags & CHANNEL_FLAG.CHANNEL_FLAG_LAST:
                    return

    # -- receiving frames from the server

    async def process_channel_data(self, data):
        if len(data) < 8:
            return
        flags = CHANNEL_FLAG(struct.unpack("<I", data[4:8])[0])
        if CHANNEL_FLAG.CHANNEL_FLAG_FIRST in flags:
            self._buffer = b""
        self._buffer += data[8:]
        if CHANNEL_FLAG.CHANNEL_FLAG_LAST not in flags:
            return
        frame, self._buffer = self._buffer, b""
        await self._dispatch(frame)

    async def process_user_data(self, data):
        pass  # nothing is pushed in from the external queue for this channel

    async def _dispatch(self, frame):
        if len(frame) < 5:
            return
        stream_id, opcode = struct.unpack("<IB", frame[:5])
        payload = frame[5:]
        if opcode in (TUN_OK, TUN_FAIL):
            waiter = self._open_waiters.get(stream_id)
            if waiter is not None and not waiter.done():
                waiter.set_result(opcode == TUN_OK)
        elif opcode == TUN_DATA:
            writer = self._streams.get(stream_id)
            if writer is not None:
                try:
                    writer.write(payload)
                    await writer.drain()
                except Exception:
                    await self._close(stream_id)
        elif opcode == TUN_CLOSE:
            await self._close(stream_id)

    async def _pump_browser(self, stream_id, reader):
        try:
            while True:
                data = await reader.read(BROWSER_READ_CHUNK)
                if not data:
                    break
                await self._send_frame(stream_id, TUN_DATA, data)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("tunnel %d browser read error: %s", stream_id, exc)
        finally:
            with contextlib.suppress(Exception):
                await self._send_frame(stream_id, TUN_CLOSE)
            await self._close(stream_id, from_pump=True)

    async def _close(self, stream_id, from_pump=False):
        writer = self._streams.pop(stream_id, None)
        task = self._tasks.pop(stream_id, None)
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()
        if task is not None and not from_pump:
            task.cancel()
