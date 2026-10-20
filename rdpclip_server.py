"""A minimal RDP server that does nothing but move clipboard data.

It implements just enough of MS-RDPBCGR for a real RDP client (mstsc, or the
Microsoft Windows App on iPad) to complete a connection, then uses the CLIPRDR
virtual channel (MS-RDPECLIP) to exchange whatever the client puts on its
clipboard - and to hand data back the other way.

There is no X server, no desktop, no graphics encoder. The client shows a black
window because we never send a single screen update - that is intentional.

Connection sequence we implement (server side):
  1. TPKT + X.224 Connection Request  -> Connection Confirm, selecting TLS
  2. TLS handshake
  3. MCS Connect Initial              -> Connect Response (carries GCC + our channel ids)
  4. MCS Erect Domain / Attach User / Channel Joins
  5. Client Info PDU (credentials)    -> we check them
  6. Server License Error PDU ("valid client", i.e. no licensing needed)
  7. Server Demand Active (our capabilities) <- Client Confirm Active
  8. Finalization: Synchronize / Control Cooperate / Control Granted / Font Map
  9. CLIPRDR in both directions:
     client -> server  for every format list the client announces we pick the
                       richest format on offer and pull it: files (via
                       FileGroupDescriptorW + File Contents Requests), text,
                       PNG, bitmaps or HTML. Files land in the inbox directory,
                       text goes to the log.
     server -> client  anything handed to the control socket is announced to
                       the connected clients, which then request it from us.

Control socket (a unix socket, one JSON object per line):
  {"cmd": "text", "text": "hello"}        -> offer text to the clients
  {"cmd": "file", "paths": ["/etc/motd"]} -> offer files to the clients
  {"cmd": "status"}                       -> list the connected clients
rdpclip_send.py is a small wrapper around it.

Usage on the server:
  python3 rdpclip_server.py --config rdpclip.json
"""
import argparse
import asyncio
import contextlib
import io
import json
import logging
import ntpath
import os
import ssl
import struct
import sys
from datetime import datetime

import asn1tools
from aardwolf.protocol.T124.GCCPDU import GCCPDU
from aardwolf.protocol.T125.MCSPDU_ver_2 import MCSPDU_ver_2

log = logging.getLogger("rdpclip")

# ---------------------------------------------------------------- constants

# X.224 TPDU codes
X224_CONNECTION_REQUEST = 0xE0
X224_CONNECTION_CONFIRM = 0xD0
X224_DATA = 0xF0

# RDP security protocols offered in the X.224 negotiation
PROTOCOL_RDP = 0x00000001  # we select "SSL" (TLS); value 1 == PROTOCOL_SSL
PROTOCOL_SSL = 0x00000001

# MCS channel ids we hand out
MCS_USER_CHANNEL_BASE = 1001  # first user gets 1001
MCS_IO_CHANNEL = 1003         # the main "I/O" channel carrying share PDUs
MCS_VC_BASE = 1004            # virtual channels start here

# Share Control Header pduType values (low 4 bits; high bits are the version)
PDUTYPE_DEMANDACTIVEPDU = 0x11
PDUTYPE_CONFIRMACTIVEPDU = 0x13
PDUTYPE_DATAPDU = 0x17

# Share Data Header pduType2 values
PDUTYPE2_CONTROL = 20
PDUTYPE2_SYNCHRONIZE = 31
PDUTYPE2_FONTLIST = 39
PDUTYPE2_FONTMAP = 40

# Control PDU actions
CTRLACTION_REQUEST_CONTROL = 1
CTRLACTION_GRANTED_CONTROL = 2
CTRLACTION_COOPERATE = 4

# Basic Security Header flags
SEC_INFO_PKT = 0x0040
SEC_LICENSE_PKT = 0x0080

# Virtual channel PDU flags
CHANNEL_FLAG_FIRST = 0x00000001
CHANNEL_FLAG_LAST = 0x00000002
CHANNEL_FLAG_SHOW_PROTOCOL = 0x00000010

# The chunk size we advertise for virtual channel data. Anything longer has to
# be split into fragments, both when we send and when we receive.
VC_CHUNK_SIZE = 1600

# CLIPRDR message types
CB_MONITOR_READY = 0x0001
CB_FORMAT_LIST = 0x0002
CB_FORMAT_LIST_RESPONSE = 0x0003
CB_FORMAT_DATA_REQUEST = 0x0004
CB_FORMAT_DATA_RESPONSE = 0x0005
CB_TEMP_DIRECTORY = 0x0006
CB_CLIP_CAPS = 0x0007
CB_FILECONTENTS_REQUEST = 0x0008
CB_FILECONTENTS_RESPONSE = 0x0009
CB_LOCK_CLIPDATA = 0x000A
CB_UNLOCK_CLIPDATA = 0x000B

# CLIPRDR message flags
CB_RESPONSE_OK = 0x0001
CB_RESPONSE_FAIL = 0x0002
CB_ASCII_NAMES = 0x0004

# CLIPRDR general capability flags
CB_USE_LONG_FORMAT_NAMES = 0x00000002
CB_STREAM_FILECLIP_ENABLED = 0x00000004
CB_FILECLIP_NO_FILE_PATHS = 0x00000008
CB_HUGE_FILE_SUPPORT_ENABLED = 0x00000020

# File Contents Request flags
FILECONTENTS_SIZE = 0x00000001
FILECONTENTS_RANGE = 0x00000002

# File descriptor flags and attributes
FD_ATTRIBUTES = 0x00000004
FD_FILESIZE = 0x00000040
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_NORMAL = 0x00000080

FILEDESCRIPTOR_SIZE = 592  # fixed size of one CLIPRDR_FILEDESCRIPTOR
DOWNLOAD_CHUNK = 64 * 1024

# Clipboard format ids. The numbered ones are the Windows standard formats; the
# named ones are registered dynamically, so their ids differ per client and we
# have to look them up by name in the client's format list.
CF_TEXT = 1
CF_DIB = 8
CF_HDROP = 15
CF_UNICODETEXT = 13
CF_DIBV5 = 17
FMT_FILEGROUP = "FileGroupDescriptorW"
FMT_PNG = "PNG"
FMT_HTML = "HTML Format"
FMT_JPEG = "JFIF"

# The format id we register for the files we offer the client. Any id from
# 0xC000 up is ours to hand out.
FILEGROUP_OFFER_ID = 0xC100

# --- our own tunnel channel ("rdptun"), carried next to the clipboard.
# This is not an RDP standard; we define it because we own both ends. TCP
# streams are multiplexed over the one channel. Each frame is:
#   stream_id (u32) · opcode (u8) · payload
# and is sent as exactly one virtual-channel message (FIRST..LAST fragments).
TUN_OPEN = 1   # client -> server: payload = port(u16) + host(utf-8)
TUN_OK = 2     # server -> client: the outbound connection is up
TUN_FAIL = 3   # server -> client: the outbound connection failed
TUN_DATA = 4   # either way: payload = raw bytes for this stream
TUN_CLOSE = 5  # either way: this stream is finished
TUN_READ_CHUNK = 3200  # bytes read from an outbound socket per DATA frame;
#                        kept small (two VC chunks) so concurrent streams
#                        interleave finely instead of waiting a full frame.

SHARE_ID = 0x103EA


# ---------------------------------------------------------------- small helpers

def u8(v):
    return struct.pack("<B", v)


def u16(v):
    return struct.pack("<H", v)


def u32(v):
    return struct.pack("<I", v)


def tpkt(payload):
    """Wrap a payload in a TPKT header (RFC 1006). Length covers the header."""
    return b"\x03\x00" + struct.pack(">H", len(payload) + 4) + payload


def x224_data(payload):
    """Wrap an MCS PDU in an X.224 Data TPDU."""
    return b"\x02\xf0\x80" + payload


def caps_set(cap_type, data):
    """A TS_CAPS_SET: type, total length, then the capability body."""
    return u16(cap_type) + u16(len(data) + 4) + data


# ---------------------------------------------------------------- clipboard data

def parse_format_list(data, long_names, ascii_names):
    """Parse a CLIPRDR_FORMAT_LIST into [(format_id, name), ...].

    Two wire formats exist. Long names are a format id followed by a
    null-terminated UTF-16 name; short names pad the name to a fixed 32 bytes.
    Which one is used was agreed during the capability exchange.
    """
    formats = []
    buf = io.BytesIO(data)
    if long_names:
        while True:
            raw = buf.read(4)
            if len(raw) < 4:
                break
            fid = struct.unpack("<I", raw)[0]
            chars = []
            while True:
                unit = buf.read(2)
                if len(unit) < 2 or unit == b"\x00\x00":
                    break
                chars.append(unit)
            formats.append((fid, b"".join(chars).decode("utf-16-le", "replace")))
    else:
        encoding = "ascii" if ascii_names else "utf-16-le"
        while True:
            entry = buf.read(36)
            if len(entry) < 36:
                break
            fid = struct.unpack("<I", entry[:4])[0]
            name = entry[4:].decode(encoding, "replace").split("\x00")[0]
            formats.append((fid, name))
    return formats


def build_format_list(formats, long_names):
    """Build a CLIPRDR_FORMAT_LIST body from [(format_id, name), ...]."""
    out = b""
    for fid, name in formats:
        if long_names:
            out += u32(fid) + name.encode("utf-16-le") + b"\x00\x00"
        else:
            out += u32(fid) + name.encode("utf-16-le").ljust(32, b"\x00")[:32]
    return out


def build_file_descriptor(name, size):
    """One CLIPRDR_FILEDESCRIPTOR for a regular file of a known size."""
    return (
        u32(FD_ATTRIBUTES | FD_FILESIZE)
        + b"\x00" * 32                 # reserved1
        + u32(FILE_ATTRIBUTE_NORMAL)
        + b"\x00" * 16                 # reserved2
        + b"\x00" * 8                  # lastWriteTime: we do not pass it on
        + u32(size >> 32)
        + u32(size & 0xFFFFFFFF)
        + name.encode("utf-16-le").ljust(520, b"\x00")[:520]
    )


def parse_file_descriptors(data):
    """Parse a CLIPRDR_FILELIST into [{name, size, is_dir}, ...]."""
    if len(data) < 4:
        return []
    count = struct.unpack("<I", data[:4])[0]
    files = []
    for i in range(count):
        off = 4 + i * FILEDESCRIPTOR_SIZE
        entry = data[off:off + FILEDESCRIPTOR_SIZE]
        if len(entry) < FILEDESCRIPTOR_SIZE:
            break
        flags = struct.unpack("<I", entry[0:4])[0]
        attrs = struct.unpack("<I", entry[36:40])[0]
        high, low = struct.unpack("<II", entry[64:72])
        name = entry[72:592].decode("utf-16-le", "replace").split("\x00")[0]
        files.append({
            "name": name,
            # The size is only meaningful when the descriptor says so; when it
            # is missing we ask the client for it with a FILECONTENTS_SIZE.
            "size": (high << 32 | low) if flags & FD_FILESIZE else None,
            "is_dir": bool(flags & FD_ATTRIBUTES and attrs & FILE_ATTRIBUTE_DIRECTORY),
        })
    return files


def bmp_from_dib(dib):
    """Turn a CF_DIB payload into a .bmp file by prepending the file header.

    CF_DIB is exactly a .bmp without its 14-byte BITMAPFILEHEADER, so we work
    out where the pixels start and write the header ourselves.
    """
    if len(dib) < 40:
        return None
    header_size = struct.unpack("<I", dib[:4])[0]
    bit_count = struct.unpack("<H", dib[14:16])[0]
    compression = struct.unpack("<I", dib[16:20])[0]
    clr_used = struct.unpack("<I", dib[32:36])[0]
    palette = clr_used * 4
    if palette == 0 and bit_count <= 8:
        palette = (1 << bit_count) * 4
    if compression in (3, 6) and header_size == 40:
        palette += 12  # BI_BITFIELDS stores three colour masks after the header
    offset = 14 + header_size + palette
    return (b"BM" + u32(14 + len(dib)) + u16(0) + u16(0) + u32(offset) + dib)


def safe_name(name, fallback="clipboard.bin"):
    """Make a client-supplied file name safe to join onto our inbox path."""
    name = (name or "").replace("\\", "/")
    name = ntpath.splitdrive(name)[1].replace("\\", "/")
    base = os.path.basename(name.rstrip("/"))
    if base in ("", ".", ".."):
        return fallback
    return base


# ---------------------------------------------------------------- GCC / MCS

class Asn1:
    """Compiled ASN.1 codecs. Compiling is slow, so we do it once."""

    def __init__(self):
        log.info("compiling ASN.1 schemas...")
        self.mcs_ber = asn1tools.compile_string(MCSPDU_ver_2, "ber")
        self.mcs_per = asn1tools.compile_string(MCSPDU_ver_2, "per")
        self.gcc = asn1tools.compile_string(GCCPDU, "per")
        log.info("ASN.1 ready")


def parse_client_gcc_userdata(blob):
    """Walk the client's GCC user data TLVs and pull out what we need.

    We only want the requested desktop size (CS_CORE) and the virtual channel
    list (CS_NET). We parse by hand because the structures are simple and
    aardwolf's parser prints debug output.
    """
    result = {"width": 1024, "height": 768, "channels": []}
    buf = io.BytesIO(blob)
    while True:
        head = buf.read(4)
        if len(head) < 4:
            break
        utype, ulen = struct.unpack("<HH", head)
        if ulen < 4:
            break
        body = buf.read(ulen - 4)
        if utype == 0xC001:  # CS_CORE
            if len(body) >= 12:
                _version, w, h = struct.unpack("<IHH", body[:8])
                result["width"], result["height"] = w, h
        elif utype == 0xC003:  # CS_NET
            if len(body) >= 4:
                count = struct.unpack("<I", body[:4])[0]
                for i in range(count):
                    off = 4 + i * 12
                    if off + 12 > len(body):
                        break
                    raw_name = body[off:off + 8]
                    options = struct.unpack("<I", body[off + 8:off + 12])[0]
                    name = raw_name.split(b"\x00")[0].decode("ascii", "replace")
                    result["channels"].append({"name": name, "options": options})
    return result


def build_server_gcc_userdata(requested_protocols, channel_ids):
    """Build the server's GCC user data: SC_CORE + SC_NET + SC_SECURITY.

    We hand-build these because aardwolf's encoders have bugs here (SC_NET
    writes a 4-byte channel id instead of 2, and SC_SECURITY cannot encode the
    "no certificate" case we need for TLS).
    """
    # SC_CORE (0x0C01): version, the protocols the client asked for, early caps
    sc_core = u32(0x00080004) + u32(requested_protocols) + u32(0x00000000)
    sc_core = u16(0x0C01) + u16(len(sc_core) + 4) + sc_core

    # SC_NET (0x0C03): the I/O channel plus one id per virtual channel.
    # Padded to a 4-byte boundary when the channel count is odd.
    net = u16(MCS_IO_CHANNEL) + u16(len(channel_ids))
    for cid in channel_ids:
        net += u16(cid)
    if len(channel_ids) % 2 != 0:
        net += b"\x00\x00"
    sc_net = u16(0x0C03) + u16(len(net) + 4) + net

    # SC_SECURITY (0x0C02): with TLS there is no RDP-level encryption, so
    # both method and level are NONE and no server certificate is sent.
    sec = u32(0x00000000) + u32(0x00000000)
    sc_sec = u16(0x0C02) + u16(len(sec) + 4) + sec

    return sc_core + sc_net + sc_sec


# ---------------------------------------------------------------- capabilities

def build_demand_active(width, height):
    """The Server Demand Active PDU: our capability sets.

    These are the minimum a client needs to agree on a session. Everything is
    sized for "we will never actually draw anything".
    """
    caps = []

    # General: say we support suppressing output, which is how a minimized
    # client tells us to stop sending screen updates (we never send any).
    general = (
        u16(1) + u16(3)        # osMajorType=windows, osMinorType=nt
        + u16(0x0200)          # protocolVersion
        + u16(0)               # pad
        + u16(0)               # generalCompressionTypes
        + u16(0x0004)          # extraFlags: NO_BITMAP_COMPRESSION_HDR
        + u16(0) + u16(0)      # updateCapabilityFlag, remoteUnshareFlag
        + u16(0)               # generalCompressionLevel
        + u8(0)                # refreshRectSupport
        + u8(1)                # suppressOutputSupport
    )
    caps.append(caps_set(1, general))

    bitmap = (
        u16(16)                # preferredBitsPerPixel
        + u16(1) + u16(1) + u16(1)   # receive 1/4/8 bpp
        + u16(width) + u16(height)
        + u16(0)               # pad
        + u16(0)               # desktopResizeFlag
        + u16(1)               # bitmapCompressionFlag
        + u8(0) + u8(0)        # highColorFlags, drawingFlags
        + u16(1)               # multipleRectangleSupport
        + u16(0)               # pad
    )
    caps.append(caps_set(2, bitmap))

    order = (
        b"\x00" * 16           # terminalDescriptor
        + u32(0)               # pad
        + u16(1) + u16(20)     # desktopSaveXGranularity / Y
        + u16(0)               # pad
        + u16(1)               # maximumOrderLevel
        + u16(0)               # numberFonts
        + u16(0x0022)          # orderFlags: NEGOTIATE | ZEROBOUNDSDELTAS
        + b"\x00" * 32         # orderSupport: we support no drawing orders
        + u16(0)               # textFlags
        + u16(0)               # orderSupportExFlags
        + u32(0)               # pad
        + u32(230400)          # desktopSaveSize
        + u16(0) + u16(0)      # pad
        + u16(0)               # textANSICodePage
        + u16(0)               # pad
    )
    caps.append(caps_set(3, order))

    pointer = u16(0) + u16(20) + u16(20)  # no color pointer, small caches
    caps.append(caps_set(8, pointer))

    # Input: we accept scancodes and unicode but never act on them.
    inputcap = (
        u16(0x0001 | 0x0004 | 0x0008 | 0x0020)  # SCANCODES|MOUSEX|FASTPATH|UNICODE
        + u16(0)
        + u32(0x00000409)      # keyboardLayout: en-US
        + u32(4)               # keyboardType
        + u32(0)               # keyboardSubType
        + u32(12)              # keyboardFunctionKey
        + b"\x00" * 64         # imeFileName
    )
    caps.append(caps_set(13, inputcap))

    # Virtual channel: this is the one that actually matters to us, because the
    # clipboard rides on a virtual channel.
    caps.append(caps_set(20, u32(0) + u32(VC_CHUNK_SIZE)))

    caps.append(caps_set(9, u16(1002) + u16(0)))  # Share

    combined = u16(len(caps)) + u16(0) + b"".join(caps)
    source = b"RDP\x00"
    body = (
        u32(SHARE_ID)
        + u16(len(source))
        + u16(len(combined))
        + source
        + combined
        + u32(0)               # sessionId
    )
    total_len = len(body) + 6
    return u16(total_len) + u16(PDUTYPE_DEMANDACTIVEPDU) + u16(MCS_IO_CHANNEL) + body


def share_data_pdu(pdu_type2, data):
    """Wrap data in a Share Control Header + Share Data Header."""
    body = (
        u32(SHARE_ID)
        + u8(0)                # pad1
        + u8(1)                # streamID = STREAM_LOW
        + u16(len(data) + 18)  # uncompressedLength (whole PDU)
        + u8(pdu_type2)
        + u8(0)                # compressedType
        + u16(0)               # compressedLength
        + data
    )
    total_len = len(body) + 6
    return u16(total_len) + u16(PDUTYPE_DATAPDU) + u16(MCS_IO_CHANNEL) + body


# ---------------------------------------------------------------- the session

class RdpClipSession:
    """Handles one client connection from TCP accept to clipboard data."""

    def __init__(self, reader, writer, asn1, config, recorder):
        self.reader = reader
        self.writer = writer
        self.asn1 = asn1
        self.config = config
        self.recorder = recorder
        self.peer = writer.get_extra_info("peername")
        self.user_channel = MCS_USER_CHANNEL_BASE
        self.channels = {}       # name -> channel id
        self.channel_names = {}  # channel id -> name
        self.width = 1024
        self.height = 768
        self.cliprdr_id = None
        self.clip_ready = False
        # One lock serialises every virtual-channel send, so the fragments of
        # two concurrent messages (e.g. two tunnel streams) never interleave.
        self.send_lock = asyncio.Lock()

        # tunnel state
        self.rdptun_id = None
        self.tun_buffer = b""     # inbound reassembly for the tunnel channel
        self.tun_streams = {}     # stream id -> outbound StreamWriter
        self.tun_tasks = {}       # stream id -> task pumping that socket back

        # clipboard state
        self.long_format_names = False   # agreed during the capability exchange
        self.vc_buffer = b""             # inbound virtual channel reassembly
        self.pending_pull = None         # the format we last asked the client for
        self.pull_queue = []             # what to ask for once that one is done
        self.client_formats = {}         # name -> format id, from the last list
        self.file_streams = {}           # our stream id -> future for the reply
        self.next_stream_id = 1
        self.pull_task = None            # the running "download from client" task
        # what we are offering the client (server -> client), by format id
        self.offers = {}
        self.file_offer = []             # the files behind our last file offer
        # A client keeps one clipboard request outstanding at a time, so we wait
        # for it to collect an offer before announcing the next one.
        self.offer_fetched = asyncio.Event()
        self.offer_fetched.set()

    # ---------------- framing

    async def read_tpkt(self):
        """Read one TPKT frame and return its payload (without the 4-byte header)."""
        head = await self.reader.readexactly(4)
        if head[0] != 0x03:
            raise ValueError("not a TPKT frame: %r" % head)
        length = struct.unpack(">H", head[2:4])[0]
        if length < 4:
            raise ValueError("bad TPKT length %d" % length)
        return await self.reader.readexactly(length - 4)

    async def send_tpkt(self, payload):
        self.writer.write(tpkt(payload))
        await self.writer.drain()

    async def read_mcs(self):
        """Read one MCS PDU out of an X.224 Data TPDU."""
        payload = await self.read_tpkt()
        li = payload[0]
        code = payload[1]
        if code != X224_DATA:
            raise ValueError("expected X.224 data, got 0x%02x" % code)
        # The length indicator counts the bytes after itself, so the X.224
        # header occupies 1 + li bytes and the MCS PDU starts right after.
        return payload[1 + li:]

    async def send_mcs(self, pdu):
        await self.send_tpkt(x224_data(pdu))

    def decode_mcs(self, pdu):
        """Decode an MCS PDU, returning (kind, body).

        The first byte of a PER-encoded DomainMCSPDU holds the CHOICE index in
        its top 6 bits. We read that first because asn1tools cannot decode
        erectDomainRequest (it trips over the unconstrained integers in it), so
        we recognise that one by tag and skip it instead of parsing.
        """
        if not pdu:
            raise ValueError("empty MCS PDU")
        choice = pdu[0] >> 2
        if choice == 1:  # erectDomainRequest - nothing in it we need
            return "erectDomainRequest", None
        return self.asn1.mcs_per.decode("DomainMCSPDU", pdu)

    async def send_on_channel(self, channel_id, data):
        """Send a payload to the client on an MCS channel (sendDataIndication)."""
        pdu = self.asn1.mcs_per.encode("DomainMCSPDU", ("sendDataIndication", {
            "initiator": self.user_channel,
            "channelId": channel_id,
            "dataPriority": "high",
            "segmentation": (b"\xc0", 2),
            "userData": data,
        }))
        await self.send_mcs(bytes(pdu))

    # ---------------- phase 1: X.224 + TLS

    async def negotiate_x224(self):
        payload = await self.read_tpkt()
        if payload[1] != X224_CONNECTION_REQUEST:
            raise ValueError("expected X.224 connection request")
        log.info("[%s] X.224 connection request", self.peer[0])

        # The client may include an RDP Negotiation Request listing the security
        # protocols it supports. We always answer "use TLS".
        nego_rsp = u8(0x02) + u8(0x00) + u16(8) + u32(PROTOCOL_SSL)
        cc = (
            u8(6 + len(nego_rsp))
            + u8(X224_CONNECTION_CONFIRM)
            + b"\x00\x00"      # dst-ref
            + b"\x12\x34"      # src-ref
            + b"\x00"          # class
            + nego_rsp
        )
        await self.send_tpkt(cc)

    async def start_tls(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.config["cert"], self.config["key"])
        # Old clients negotiate down; let them.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        transport = self.writer.transport
        protocol = transport.get_protocol()
        loop = asyncio.get_event_loop()
        new_transport = await loop.start_tls(transport, protocol, ctx, server_side=True)
        self.writer._transport = new_transport
        self.reader._transport = new_transport
        log.info("[%s] TLS established", self.peer[0])

    # ---------------- phase 2: MCS

    async def mcs_connect(self):
        pdu = await self.read_mcs()
        decoded = self.asn1.mcs_ber.decode("ConnectMCSPDU", pdu)
        if decoded[0] != "connect-initial":
            raise ValueError("expected connect-initial, got %s" % decoded[0])

        # Dig the client's GCC user data out of the T.124 wrapper.
        conn_data = self.asn1.gcc.decode("ConnectData", decoded[1]["userData"])
        raw = decoded[1]["userData"]
        inner = conn_data["connectPDU"]
        # asn1tools can under-read the trailing bytes of connectPDU, so splice
        # the remainder back on before decoding (same workaround aardwolf uses).
        pos = raw.find(inner)
        if pos >= 0:
            inner = inner + raw[pos + len(inner):]
        gcc_pdu = self.asn1.gcc.decode("ConnectGCCPDU", inner)
        client_ud = gcc_pdu[1]["userData"][0]["value"]

        info = parse_client_gcc_userdata(client_ud)
        self.width, self.height = info["width"], info["height"]
        requested = info["channels"]
        log.info("[%s] client wants %dx%d, channels: %s",
                 self.peer[0], self.width, self.height,
                 [c["name"] for c in requested] or "none")

        # Assign a channel id to each virtual channel the client asked for.
        channel_ids = []
        for i, chan in enumerate(requested):
            cid = MCS_VC_BASE + i
            channel_ids.append(cid)
            self.channels[chan["name"]] = cid
            self.channel_names[cid] = chan["name"]
            if chan["name"].lower() == "cliprdr":
                self.cliprdr_id = cid
            elif chan["name"].lower() == "rdptun" and self.config.get("tunnel", True):
                self.rdptun_id = cid
        if self.cliprdr_id is None and self.rdptun_id is None:
            raise ValueError("client requested neither cliprdr nor rdptun")

        server_ud = build_server_gcc_userdata(PROTOCOL_SSL, channel_ids)
        gcc_response = self.asn1.gcc.encode("ConnectGCCPDU", ("conferenceCreateResponse", {
            "nodeID": MCS_USER_CHANNEL_BASE,
            "tag": 1,
            "result": "success",
            "userData": [{"key": ("h221NonStandard", b"McDn"), "value": server_ud}],
        }))
        connect_data = self.asn1.gcc.encode("ConnectData", {
            "t124Identifier": ("object", "0.0.20.124.0.1"),
            "connectPDU": bytes(gcc_response),
        })
        response = self.asn1.mcs_ber.encode("ConnectMCSPDU", ("connect-response", {
            "result": "rt-successful",
            "calledConnectId": 0,
            "domainParameters": {
                "maxChannelIds": 34,
                "maxUserIds": 3,
                "maxTokenIds": 0,
                "numPriorities": 1,
                "minThroughput": 0,
                "maxHeight": 1,
                "maxMCSPDUsize": 65535,
                "protocolVersion": 2,
            },
            "userData": bytes(connect_data),
        }))
        await self.send_mcs(bytes(response))
        log.info("[%s] MCS connect-response sent (cliprdr=%d)", self.peer[0], self.cliprdr_id)

    async def mcs_setup_channels(self):
        """Answer Erect Domain / Attach User / Channel Join until the session starts.

        We deliberately do not require a fixed set of joins. Clients differ in
        which channels they bother to join (some skip the user channel), so we
        just answer whatever arrives and stop at the first real share PDU -
        which is the Client Info PDU. That PDU is handed back to the caller.
        """
        joined = []
        while True:
            pdu = await self.read_mcs()
            kind, body = self.decode_mcs(pdu)
            if kind == "erectDomainRequest":
                log.debug("[%s] erect domain", self.peer[0])
            elif kind == "attachUserRequest":
                confirm = self.asn1.mcs_per.encode("DomainMCSPDU", ("attachUserConfirm", {
                    "result": "rt-successful",
                    "initiator": self.user_channel,
                }))
                await self.send_mcs(bytes(confirm))
                log.debug("[%s] attach user -> %d", self.peer[0], self.user_channel)
            elif kind == "channelJoinRequest":
                cid = body["channelId"]
                confirm = self.asn1.mcs_per.encode("DomainMCSPDU", ("channelJoinConfirm", {
                    "result": "rt-successful",
                    "initiator": body["initiator"],
                    "requested": cid,
                    "channelId": cid,
                }))
                await self.send_mcs(bytes(confirm))
                joined.append(cid)
            elif kind == "sendDataRequest":
                log.info("[%s] channels joined: %s", self.peer[0], joined)
                return body["channelId"], body["userData"]
            elif kind == "disconnectProviderUltimatum":
                raise ConnectionResetError("client disconnected during setup")
            else:
                log.debug("[%s] ignoring MCS %s during setup", self.peer[0], kind)

    # ---------------- phase 3: login + activation

    async def read_channel_data(self):
        """Read the next sendDataRequest, returning (channel_id, payload)."""
        while True:
            pdu = await self.read_mcs()
            kind, body = self.decode_mcs(pdu)
            if kind == "sendDataRequest":
                return body["channelId"], body["userData"]
            if kind in ("disconnectProviderUltimatum",):
                raise ConnectionResetError("client disconnected")
            log.debug("[%s] ignoring MCS %s", self.peer[0], kind)

    async def handle_client_info(self, data):
        """Check the credentials in the Client Info PDU, then finish licensing."""
        flags = struct.unpack("<H", data[:2])[0]
        if not flags & SEC_INFO_PKT:
            raise ValueError("expected the client info PDU")
        info = data[4:]  # skip the basic security header

        code_page, info_flags = struct.unpack("<II", info[:8])
        lengths = struct.unpack("<HHHHH", info[8:18])
        cb_domain, cb_user, cb_password = lengths[0], lengths[1], lengths[2]
        unicode_strings = bool(info_flags & 0x00000010)

        pos = 18
        def take(nbytes):
            nonlocal pos
            raw = info[pos:pos + nbytes]
            pos += nbytes + (2 if unicode_strings else 1)
            if unicode_strings:
                return raw.decode("utf-16-le", "replace")
            return raw.decode("latin-1", "replace")

        domain = take(cb_domain)
        username = take(cb_user)
        password = take(cb_password)

        want_user = self.config.get("user")
        want_pass = self.config.get("password")
        if username != want_user or password != want_pass:
            log.warning("[%s] rejected login for user %r", self.peer[0], username)
            raise PermissionError("bad credentials")
        log.info("[%s] login OK for %r (domain %r)", self.peer[0], username, domain)

        # Tell the client no licensing is required.
        license_body = (
            u8(0xFF)           # bMsgType = ERROR_ALERT
            + u8(0x03)         # flags: preamble version 3
            + u16(16)          # wMsgSize
            + u32(0x00000007)  # dwErrorCode = STATUS_VALID_CLIENT
            + u32(0x00000002)  # dwStateTransition = ST_NO_TRANSITION
            + u16(0x0004)      # wBlobType
            + u16(0x0000)      # wBlobLen
        )
        await self.send_on_channel(
            MCS_IO_CHANNEL, u16(SEC_LICENSE_PKT) + u16(0) + license_body)
        log.debug("[%s] licensing done", self.peer[0])

    async def activate(self):
        """Exchange capabilities and run the finalization handshake."""
        await self.send_on_channel(MCS_IO_CHANNEL, build_demand_active(self.width, self.height))
        log.debug("[%s] demand active sent", self.peer[0])

        # Wait for Confirm Active. We do not care what the client supports,
        # since we never draw, so we only check that it arrived.
        while True:
            channel_id, data = await self.read_channel_data()
            if len(data) < 6:
                continue
            pdu_type = struct.unpack("<H", data[2:4])[0]
            if pdu_type == PDUTYPE_CONFIRMACTIVEPDU:
                log.debug("[%s] confirm active received", self.peer[0])
                break

        # Server half of the finalization sequence.
        await self.send_on_channel(
            MCS_IO_CHANNEL, share_data_pdu(PDUTYPE2_SYNCHRONIZE, u16(1) + u16(self.user_channel)))
        await self.send_on_channel(
            MCS_IO_CHANNEL,
            share_data_pdu(PDUTYPE2_CONTROL, u16(CTRLACTION_COOPERATE) + u16(0) + u32(0)))
        await self.send_on_channel(
            MCS_IO_CHANNEL,
            share_data_pdu(PDUTYPE2_CONTROL,
                           u16(CTRLACTION_GRANTED_CONTROL) + u16(self.user_channel)
                           + u32(MCS_IO_CHANNEL)))
        await self.send_on_channel(
            MCS_IO_CHANNEL,
            share_data_pdu(PDUTYPE2_FONTMAP, u16(0) + u16(0) + u16(0x0003) + u16(4)))
        log.info("[%s] session active", self.peer[0])

    # ---------------- phase 4: the clipboard

    async def send_vc(self, channel_id, msg):
        """Send one virtual-channel message, split to the advertised chunk size.

        The whole thing is one FIRST..LAST fragment group; the receiver
        reassembles on those flags. The lock keeps two concurrent messages from
        interleaving their chunks on the shared channel.
        """
        total = len(msg)
        async with self.send_lock:
            offset = 0
            while True:
                chunk = msg[offset:offset + VC_CHUNK_SIZE]
                vc_flags = CHANNEL_FLAG_SHOW_PROTOCOL
                if offset == 0:
                    vc_flags |= CHANNEL_FLAG_FIRST
                offset += len(chunk)
                if offset >= total:
                    vc_flags |= CHANNEL_FLAG_LAST
                # The length field carries the total length, not the chunk's.
                await self.send_on_channel(channel_id,
                                           u32(total) + u32(vc_flags) + chunk)
                if vc_flags & CHANNEL_FLAG_LAST:
                    return

    async def send_cliprdr(self, msg_type, flags, data=b""):
        """Send one CLIPRDR message on the clipboard channel."""
        await self.send_vc(self.cliprdr_id,
                           u16(msg_type) + u16(flags) + u32(len(data)) + data)

    async def start_clipboard(self):
        """Announce our clipboard capabilities and open the channel."""
        flags = (CB_USE_LONG_FORMAT_NAMES | CB_STREAM_FILECLIP_ENABLED
                 | CB_FILECLIP_NO_FILE_PATHS | CB_HUGE_FILE_SUPPORT_ENABLED)
        caps = (
            u16(1) + u16(0)        # cCapabilitiesSets, pad
            + u16(1) + u16(12)     # capabilitySetType=GENERAL, lengthCapability
            + u32(2)               # version 2
            + u32(flags)
        )
        await self.send_cliprdr(CB_CLIP_CAPS, 0, caps)
        await self.send_cliprdr(CB_MONITOR_READY, 0)
        self.clip_ready = True
        log.info("[%s] clipboard ready - copy text or files on the client",
                 self.peer[0])

    async def handle_cliprdr(self, payload):
        """Reassemble virtual channel fragments into one CLIPRDR message."""
        if len(payload) < 8:
            return
        _total, vc_flags = struct.unpack("<II", payload[:8])
        if vc_flags & CHANNEL_FLAG_FIRST:
            self.vc_buffer = b""
        self.vc_buffer += payload[8:]
        if not vc_flags & CHANNEL_FLAG_LAST:
            return
        msg, self.vc_buffer = self.vc_buffer, b""
        if len(msg) < 8:
            return
        msg_type, msg_flags, data_len = struct.unpack("<HHI", msg[:8])
        await self.dispatch_cliprdr(msg_type, msg_flags, msg[8:8 + data_len])

    async def dispatch_cliprdr(self, msg_type, msg_flags, data):
        if msg_type == CB_CLIP_CAPS:
            self.read_client_caps(data)
        elif msg_type == CB_FORMAT_LIST:
            await self.handle_format_list(msg_flags, data)
        elif msg_type == CB_FORMAT_DATA_RESPONSE:
            await self.handle_format_data_response(msg_flags, data)
        elif msg_type == CB_FORMAT_DATA_REQUEST:
            await self.handle_format_data_request(data)
        elif msg_type == CB_FILECONTENTS_REQUEST:
            await self.handle_filecontents_request(data)
        elif msg_type == CB_FILECONTENTS_RESPONSE:
            self.handle_filecontents_response(msg_flags, data)
        elif msg_type == CB_FORMAT_LIST_RESPONSE:
            if not msg_flags & CB_RESPONSE_OK:
                log.warning("[%s] client refused what we offered", self.peer[0])
            else:
                log.debug("[%s] client accepted our offer", self.peer[0])
        elif msg_type in (CB_TEMP_DIRECTORY, CB_LOCK_CLIPDATA, CB_UNLOCK_CLIPDATA):
            pass  # nothing we need to act on
        else:
            log.debug("[%s] unhandled clipboard message 0x%04x", self.peer[0], msg_type)

    def read_client_caps(self, data):
        """Work out whether we and the client both speak long format names."""
        client_flags = 0
        if len(data) >= 4:
            count = struct.unpack("<H", data[:2])[0]
            pos = 4
            for _ in range(count):
                if pos + 4 > len(data):
                    break
                set_type, set_len = struct.unpack("<HH", data[pos:pos + 4])
                if set_type == 1 and set_len >= 12:
                    client_flags = struct.unpack("<I", data[pos + 8:pos + 12])[0]
                pos += max(set_len, 4)
        self.long_format_names = bool(client_flags & CB_USE_LONG_FORMAT_NAMES)
        log.debug("[%s] client clipboard flags 0x%08x (long names: %s)",
                  self.peer[0], client_flags, self.long_format_names)

    # -- client -> server

    async def handle_format_list(self, msg_flags, data):
        """The client copied something. Acknowledge, then pull the best format."""
        await self.send_cliprdr(CB_FORMAT_LIST_RESPONSE, CB_RESPONSE_OK)
        formats = parse_format_list(data, self.long_format_names,
                                    bool(msg_flags & CB_ASCII_NAMES))
        self.client_formats = {name: fid for fid, name in formats if name}
        ids = {fid for fid, _ in formats}
        log.debug("[%s] client offers: %s", self.peer[0],
                  [(fid, name) for fid, name in formats])

        # Richest first: a file carries anything, so it wins over a rendering
        # of the same content.
        choice = None
        for name, kind in ((FMT_FILEGROUP, "files"), (FMT_PNG, "png"),
                           (FMT_JPEG, "jpeg"), (FMT_HTML, "html")):
            if name in self.client_formats:
                choice = (kind, self.client_formats[name])
                break
        if choice is None:
            for fid, kind in ((CF_UNICODETEXT, "text"), (CF_DIBV5, "dib"),
                              (CF_DIB, "dib"), (CF_TEXT, "ansitext")):
                if fid in ids:
                    choice = (kind, fid)
                    break
        if choice is None:
            log.debug("[%s] nothing we can use in the format list", self.peer[0])
            return
        # Only the newest list matters - that is what the clipboard holds now -
        # but we must not drop it just because an earlier request is still in
        # flight. Clients announce every format they could ever produce as soon
        # as the channel opens, and the real copy follows right behind it.
        self.pull_queue = [choice]
        await self.pump_pull()

    async def pump_pull(self):
        """Ask the client for the queued format, if nothing else is in flight."""
        if self.pending_pull is not None or not self.pull_queue:
            return
        if self.pull_task is not None and not self.pull_task.done():
            return  # a file transfer owns the channel; it pumps us when it ends
        kind, fid = self.pull_queue.pop()
        self.pull_queue.clear()
        self.pending_pull = kind
        await self.send_cliprdr(CB_FORMAT_DATA_REQUEST, 0, u32(fid))
        log.debug("[%s] requested format %s (%s)", self.peer[0], fid, kind)

    async def handle_format_data_response(self, msg_flags, data):
        """The client handed over the data we asked for."""
        kind, self.pending_pull = self.pending_pull, None
        if kind is None:
            return
        if not msg_flags & CB_RESPONSE_OK:
            # Normal right after connect: clients announce every format they
            # could ever produce before anything has been copied.
            log.debug("[%s] client has no %s to give", self.peer[0], kind)
            await self.pump_pull()
            return

        if kind == "files":
            files = parse_file_descriptors(data)
            log.info("[%s] client offers %d file(s): %s", self.peer[0], len(files),
                     [f["name"] for f in files])
            self.pull_task = asyncio.ensure_future(self.download_from_client(files))
            return  # the transfer pumps the queue when it finishes
        if kind == "text":
            # Trim to a whole number of UTF-16 code units; some clients pad the
            # payload with a stray byte, which would decode to a junk character.
            usable = data[:len(data) // 2 * 2]
            text = usable.decode("utf-16-le", "replace").rstrip("\x00")
            if text:
                self.recorder.text(self.peer[0], text)
        elif kind == "ansitext":
            text = data.decode("cp1252", "replace").rstrip("\x00")
            if text:
                self.recorder.text(self.peer[0], text)
        elif kind == "png":
            self.recorder.blob(self.peer[0], "clipboard.png", data)
        elif kind == "jpeg":
            self.recorder.blob(self.peer[0], "clipboard.jpg", data)
        elif kind == "html":
            self.recorder.blob(self.peer[0], "clipboard.html", data)
        elif kind == "dib":
            bmp = bmp_from_dib(data)
            if bmp is None:
                log.warning("[%s] could not read the bitmap header", self.peer[0])
            else:
                self.recorder.blob(self.peer[0], "clipboard.bmp", bmp)
        await self.pump_pull()

    async def download_from_client(self, files):
        """Stream every file the client offered into our inbox."""
        for index, entry in enumerate(files):
            if entry["is_dir"]:
                continue
            try:
                size = entry["size"]
                if size is None:
                    # The descriptor did not carry one, so ask.
                    size = await self.request_file_contents(index, FILECONTENTS_SIZE)
                path = self.recorder.inbox_path(safe_name(entry["name"]))
                written = 0
                with open(path, "wb") as fh:
                    while written < size:
                        want = min(DOWNLOAD_CHUNK, size - written)
                        chunk = await self.request_file_contents(
                            index, FILECONTENTS_RANGE, written, want)
                        if not chunk:
                            break  # the client stopped giving data
                        fh.write(chunk)
                        written += len(chunk)
                self.recorder.file_received(self.peer[0], path, written, size)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.error("[%s] download of %r failed: %s",
                          self.peer[0], entry["name"], exc)
        # Let anything the client announced while we were busy through.
        self.pull_task = None
        await self.pump_pull()

    async def request_file_contents(self, index, flags, position=0, requested=8):
        """Ask the client for a file's size or a byte range of it."""
        stream_id = self.next_stream_id
        self.next_stream_id += 1
        future = asyncio.get_event_loop().create_future()
        self.file_streams[stream_id] = future
        body = (
            u32(stream_id)
            + u32(index)
            + u32(flags)
            + u32(position & 0xFFFFFFFF)
            + u32(position >> 32)
            + u32(requested)
        )
        try:
            await self.send_cliprdr(CB_FILECONTENTS_REQUEST, 0, body)
            raw = await asyncio.wait_for(future, timeout=30)
        finally:
            self.file_streams.pop(stream_id, None)
        if flags == FILECONTENTS_SIZE:
            return struct.unpack("<Q", raw[:8])[0] if len(raw) >= 8 else 0
        return raw

    def handle_filecontents_response(self, msg_flags, data):
        if len(data) < 4:
            return
        stream_id = struct.unpack("<I", data[:4])[0]
        future = self.file_streams.get(stream_id)
        if future is None or future.done():
            log.debug("[%s] file contents for an unknown stream %d",
                      self.peer[0], stream_id)
            return
        if not msg_flags & CB_RESPONSE_OK:
            future.set_exception(RuntimeError("client refused the file contents"))
        else:
            future.set_result(data[4:])

    # -- server -> client

    async def offer_text(self, text):
        await self.wait_until_fetched()
        self.offers[CF_UNICODETEXT] = {"kind": "text", "text": text}
        await self.announce_offer([(CF_UNICODETEXT, "")], "text")

    async def offer_files(self, paths):
        await self.wait_until_fetched()
        files = [{"path": p, "name": os.path.basename(p),
                  "size": os.path.getsize(p)} for p in paths]
        self.offers[FILEGROUP_OFFER_ID] = {"kind": "files", "files": files}
        # A File Contents Request only carries an index into the newest list.
        self.file_offer = files
        await self.announce_offer([(FILEGROUP_OFFER_ID, FMT_FILEGROUP)], "files")

    async def wait_until_fetched(self):
        """Hold off until the client has collected the previous offer.

        A client tracks one outstanding clipboard request, so announcing a
        second thing while it is still fetching the first makes it attribute our
        answer to the wrong format.
        """
        try:
            await asyncio.wait_for(self.offer_fetched.wait(), timeout=5)
        except asyncio.TimeoutError:
            log.debug("[%s] client never collected the last offer, going ahead",
                      self.peer[0])

    async def announce_offer(self, formats, kind):
        """Tell the client we have something, so it can ask us for it."""
        if not self.clip_ready:
            return
        self.offer_fetched.clear()
        body = build_format_list(formats, self.long_format_names)
        await self.send_cliprdr(CB_FORMAT_LIST, 0, body)
        log.info("[%s] offered %s to the client", self.peer[0], kind)

    async def handle_format_data_request(self, data):
        """The client is asking us for what we offered."""
        if len(data) < 4:
            return
        fid = struct.unpack("<I", data[:4])[0]
        # CF_TEXT is the same string, just narrower.
        offer = self.offers.get(CF_UNICODETEXT if fid == CF_TEXT else fid)
        payload = None
        if offer is not None and offer["kind"] == "text":
            if fid == CF_TEXT:
                payload = offer["text"].encode("cp1252", "replace") + b"\x00"
            else:
                payload = offer["text"].encode("utf-16-le") + b"\x00\x00"
        elif offer is not None and offer["kind"] == "files":
            payload = u32(len(offer["files"])) + b"".join(
                build_file_descriptor(f["name"], f["size"]) for f in offer["files"])
        if payload is None:
            log.debug("[%s] client asked for format %d, which we do not hold",
                      self.peer[0], fid)
            await self.send_cliprdr(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL)
        else:
            await self.send_cliprdr(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, payload)
            log.debug("[%s] handed over format %d (%s)",
                      self.peer[0], fid, offer["kind"])
        self.offer_fetched.set()

    async def handle_filecontents_request(self, data):
        """The client wants the bytes of a file we offered."""
        if len(data) < 24:
            return
        stream_id, index, flags, pos_low, pos_high, requested = struct.unpack(
            "<IIIIII", data[:24])
        position = pos_high << 32 | pos_low
        entry = None
        if 0 <= index < len(self.file_offer):
            entry = self.file_offer[index]
        if entry is None:
            await self.send_cliprdr(CB_FILECONTENTS_RESPONSE, CB_RESPONSE_FAIL,
                                    u32(stream_id))
            return
        try:
            if flags == FILECONTENTS_SIZE:
                body = u32(stream_id) + struct.pack(
                    "<Q", os.path.getsize(entry["path"]))
            else:
                with open(entry["path"], "rb") as fh:
                    fh.seek(position)
                    body = u32(stream_id) + fh.read(min(requested, DOWNLOAD_CHUNK))
        except OSError as exc:
            log.error("[%s] cannot read %s: %s", self.peer[0], entry["path"], exc)
            await self.send_cliprdr(CB_FILECONTENTS_RESPONSE, CB_RESPONSE_FAIL,
                                    u32(stream_id))
            return
        await self.send_cliprdr(CB_FILECONTENTS_RESPONSE, CB_RESPONSE_OK, body)

    # ---------------- phase 5: the tunnel

    async def send_tun(self, stream_id, opcode, payload=b""):
        await self.send_vc(self.rdptun_id, u32(stream_id) + u8(opcode) + payload)

    async def handle_rdptun(self, payload):
        """Reassemble virtual channel fragments into one tunnel frame."""
        if len(payload) < 8:
            return
        _total, vc_flags = struct.unpack("<II", payload[:8])
        if vc_flags & CHANNEL_FLAG_FIRST:
            self.tun_buffer = b""
        self.tun_buffer += payload[8:]
        if not vc_flags & CHANNEL_FLAG_LAST:
            return
        frame, self.tun_buffer = self.tun_buffer, b""
        await self.dispatch_tun(frame)

    async def dispatch_tun(self, frame):
        if len(frame) < 5:
            return
        stream_id = struct.unpack("<I", frame[:4])[0]
        opcode = frame[4]
        payload = frame[5:]
        if opcode == TUN_OPEN:
            if len(payload) < 2:
                return
            port = struct.unpack("<H", payload[:2])[0]
            host = payload[2:].decode("utf-8", "replace")
            asyncio.ensure_future(self.open_stream(stream_id, host, port))
        elif opcode == TUN_DATA:
            writer = self.tun_streams.get(stream_id)
            if writer is not None:
                try:
                    writer.write(payload)
                    await writer.drain()
                except Exception:
                    await self.close_stream(stream_id)
        elif opcode == TUN_CLOSE:
            await self.close_stream(stream_id)

    async def open_stream(self, stream_id, host, port):
        """Dial the destination the client asked for and relay it back."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=15)
        except Exception as exc:
            log.info("[%s] tunnel %d open %s:%s failed: %s",
                     self.peer[0], stream_id, host, port, exc)
            await self.send_tun(stream_id, TUN_FAIL)
            return
        self.tun_streams[stream_id] = writer
        await self.send_tun(stream_id, TUN_OK)
        log.info("[%s] tunnel %d -> %s:%s", self.peer[0], stream_id, host, port)
        self.tun_tasks[stream_id] = asyncio.ensure_future(
            self.pump_stream(stream_id, reader))

    async def pump_stream(self, stream_id, reader):
        """Read from the outbound socket and send it to the client as DATA."""
        try:
            while True:
                data = await reader.read(TUN_READ_CHUNK)
                if not data:
                    break
                await self.send_tun(stream_id, TUN_DATA, data)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.debug("[%s] tunnel %d read error: %s", self.peer[0], stream_id, exc)
        finally:
            await self.send_tun(stream_id, TUN_CLOSE)
            await self.close_stream(stream_id, from_pump=True)

    async def close_stream(self, stream_id, from_pump=False):
        writer = self.tun_streams.pop(stream_id, None)
        task = self.tun_tasks.pop(stream_id, None)
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()
        # The pump calls us from its own finally; don't cancel ourselves.
        if task is not None and not from_pump:
            task.cancel()

    def close_all_tunnels(self):
        for task in list(self.tun_tasks.values()):
            task.cancel()
        for writer in list(self.tun_streams.values()):
            with contextlib.suppress(Exception):
                writer.close()
        self.tun_tasks.clear()
        self.tun_streams.clear()

    # ---------------- the main loop

    async def run_session(self):
        """Main loop once the session is active: route channel data."""
        while True:
            channel_id, data = await self.read_channel_data()
            if self.cliprdr_id is not None and channel_id == self.cliprdr_id:
                await self.handle_cliprdr(data)
            elif self.rdptun_id is not None and channel_id == self.rdptun_id:
                await self.handle_rdptun(data)
            else:
                # Input, suppress-output, refresh-rect and friends. We have no
                # screen, so there is nothing to do with any of them.
                pass

    async def serve(self):
        await self.negotiate_x224()
        await self.start_tls()
        await self.mcs_connect()
        _channel, info_pdu = await self.mcs_setup_channels()
        await self.handle_client_info(info_pdu)
        await self.activate()
        if self.cliprdr_id is not None:
            await self.start_clipboard()
        if self.rdptun_id is not None:
            log.info("[%s] tunnel channel ready (id %d)", self.peer[0], self.rdptun_id)
        await self.run_session()


# ---------------------------------------------------------------- server glue

class Recorder:
    """Where clipboard data from the clients ends up.

    Text is appended to a log file; anything else is written into the inbox
    directory under a timestamped name, so nothing overwrites anything.
    """

    def __init__(self, logfile, inbox):
        self.logfile = logfile
        self.inbox = inbox
        if inbox:
            os.makedirs(inbox, exist_ok=True)

    def _log(self, line):
        log.info("%s", line)
        if self.logfile:
            stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(self.logfile, "a", encoding="utf-8") as fh:
                fh.write("%s  %s\n" % (stamp, line))

    def text(self, peer, text):
        self._log("[%s]  %s" % (peer, text))

    def inbox_path(self, name):
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        return os.path.join(self.inbox, "%s_%s" % (stamp, name))

    def blob(self, peer, name, data):
        path = self.inbox_path(name)
        with open(path, "wb") as fh:
            fh.write(data)
        self._log("[%s]  <%s, %d bytes> %s" % (peer, name, len(data), path))

    def file_received(self, peer, path, written, expected):
        short = "%s (%d bytes)" % (os.path.basename(path), written)
        if expected and written != expected:
            short += " INCOMPLETE, expected %d" % expected
        self._log("[%s]  <file> %s" % (peer, short))


class ControlServer:
    """A unix socket that lets anything on the box send data to the clients.

    One JSON object per line in, one JSON object per line out. This is how the
    server -> client direction is driven; rdpclip_send.py is a thin wrapper.
    """

    def __init__(self, path, sessions):
        self.path = path
        self.sessions = sessions

    async def start(self):
        if os.path.exists(self.path):
            os.unlink(self.path)
        server = await asyncio.start_unix_server(self.handle, self.path)
        os.chmod(self.path, 0o600)
        log.info("control socket at %s", self.path)
        return server

    def ready_sessions(self):
        return [s for s in self.sessions if s.clip_ready]

    async def handle(self, reader, writer):
        try:
            line = await reader.readline()
            if not line:
                return
            try:
                request = json.loads(line)
            except ValueError as exc:
                await self.reply(writer, {"ok": False, "error": "bad json: %s" % exc})
                return
            await self.reply(writer, await self.run(request))
        except Exception as exc:
            log.error("control request failed: %s", exc, exc_info=True)
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def reply(self, writer, obj):
        writer.write((json.dumps(obj) + "\n").encode("utf-8"))
        await writer.drain()

    async def run(self, request):
        cmd = request.get("cmd")
        clients = self.ready_sessions()
        if cmd == "status":
            return {"ok": True, "clients": [s.peer[0] for s in clients]}
        if not clients:
            return {"ok": False, "error": "no client connected"}

        if cmd == "text":
            text = request.get("text")
            if not isinstance(text, str) or text == "":
                return {"ok": False, "error": "need a non-empty 'text'"}
            for session in clients:
                await session.offer_text(text)
            return {"ok": True, "sent_to": [s.peer[0] for s in clients],
                    "kind": "text", "chars": len(text)}

        if cmd == "file":
            paths = request.get("paths") or []
            if not paths:
                return {"ok": False, "error": "need 'paths'"}
            for path in paths:
                if not os.path.isfile(path):
                    return {"ok": False, "error": "not a file: %s" % path}
            for session in clients:
                await session.offer_files(paths)
            return {"ok": True, "sent_to": [s.peer[0] for s in clients],
                    "kind": "files", "files": [os.path.basename(p) for p in paths]}

        return {"ok": False, "error": "unknown cmd %r" % cmd}


async def amain(config):
    asn1 = Asn1()
    recorder = Recorder(config.get("logfile"), config["inbox"])
    sessions = set()

    async def handle(reader, writer):
        peer = writer.get_extra_info("peername")
        session = RdpClipSession(reader, writer, asn1, config, recorder)
        sessions.add(session)
        try:
            await session.serve()
        except (asyncio.IncompleteReadError, ConnectionResetError, ConnectionAbortedError):
            log.info("[%s] disconnected", peer[0] if peer else "?")
        except PermissionError:
            pass
        except Exception as exc:
            log.error("[%s] session failed: %s", peer[0] if peer else "?", exc, exc_info=True)
        finally:
            sessions.discard(session)
            if session.pull_task is not None:
                session.pull_task.cancel()
            session.close_all_tunnels()
            with contextlib.suppress(Exception):
                writer.close()

    control = await ControlServer(config["control"], sessions).start()
    server = await asyncio.start_server(handle, config["host"], config["port"])
    log.info("listening on %s:%s", config["host"], config["port"])
    async with server, control:
        await server.serve_forever()


def main():
    ap = argparse.ArgumentParser(description="Clipboard-only RDP server")
    ap.add_argument("--config", default="rdpclip.json")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        stream=sys.stdout,
    )

    with open(args.config, encoding="utf-8") as fh:
        config = json.load(fh)
    config.setdefault("host", "0.0.0.0")
    config.setdefault("port", 3389)
    here = os.path.dirname(os.path.abspath(args.config))
    config.setdefault("inbox", os.path.join(here, "inbox"))
    config.setdefault("control", os.path.join(here, "control.sock"))

    try:
        asyncio.run(amain(config))
    except KeyboardInterrupt:
        log.info("stopped")


if __name__ == "__main__":
    main()
