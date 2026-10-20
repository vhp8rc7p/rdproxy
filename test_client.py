"""Test client for our own RDP server: connect, send one text, exit.

This exists to give us a fast, fully visible test loop. It uses aardwolf as an
RDP client and pushes one string through the clipboard channel.

Usage: python test_client.py "some text"
"""
import asyncio
import json
import logging
import sys
from pathlib import Path
from urllib.parse import quote

from aardwolf.commons.factory import RDPConnectionFactory
from aardwolf.commons.iosettings import RDPIOSettings
from aardwolf.commons.queuedata import RDPDATATYPE

CONFIG = Path(__file__).with_name("clip_sender.json")


async def main(text):
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)-7s %(message)s")
    logging.getLogger("aardwolf").setLevel(logging.DEBUG)
    cfg = json.loads(CONFIG.read_text(encoding="utf-8"))

    io = RDPIOSettings()
    io.video_width, io.video_height = 1024, 768
    io.clipboard_use_pyperclip = False
    url = "rdp+plain://%s:%s@%s:%s" % (
        quote(cfg["user"], safe=""), quote(cfg["password"], safe=""),
        cfg["host"], cfg["port"])

    conn = RDPConnectionFactory.from_url(url, io).get_connection(io)
    print("connecting to %s:%s ..." % (cfg["host"], cfg["port"]), flush=True)
    _, err = await conn.connect()
    if err is not None:
        print("CONNECT FAILED: %r" % (err,), flush=True)
        return 1
    print("CONNECTED", flush=True)

    ready = asyncio.Event()

    async def pump():
        while True:
            item = await conn.ext_out_queue.get()
            if item is None:
                print("disconnected", flush=True)
                return
            if item.type == RDPDATATYPE.CLIPBOARD_READY:
                print("clipboard channel ready", flush=True)
                ready.set()
            elif item.type == RDPDATATYPE.CLIPBOARD_FORMAT_LIST_RESPONSE:
                print("server accepted our format list: %s" % item.accepted, flush=True)

    task = asyncio.ensure_future(pump())
    try:
        await asyncio.wait_for(ready.wait(), timeout=20)
    except asyncio.TimeoutError:
        print("clipboard channel never became ready", flush=True)
        return 2

    print("sending: %s" % text, flush=True)
    await conn.set_current_clipboard_text(text)
    # The server fetches the text on demand, so stay connected a moment.
    await asyncio.sleep(6)
    task.cancel()
    await conn.terminate()
    print("done", flush=True)
    return 0


if __name__ == "__main__":
    msg = sys.argv[1] if len(sys.argv) > 1 else "hello from test_client"
    sys.exit(asyncio.run(main(msg)))
