# rdpclip — a from-scratch RDP server that moves data, not pixels

A minimal RDP server (Linux) and a Python client that use RDP's virtual
channels for what they're good at — moving data — while never sending a single
frame of screen. No X server, no desktop, no graphics encoder.

Two things ride the channels:

- **Clipboard** (MS-RDPECLIP): send text and files between a PC and the server,
  both directions.
- **A TCP tunnel** over a custom channel: a local **SOCKS5** proxy on the PC
  whose traffic exits from the **server's** IP — the same capability as
  `rdp2tcp`'s SOCKS mode or `ssh -D`, but built on a channel we define, so it
  needs no agent binary or client-side DLL.

Unusually, **the Linux box is the RDP _server_.** The known tunneling tools
(`rdp2tcp`, SocksOverRDP) put their agent on a *Windows* session host; here the
server is our own code and speaks the protocol from the TCP handshake up.

> Educational project for your own machines. The tunnel makes the server an
> authenticated forward relay — run it only on infrastructure you control, and
> remember that a client's traffic leaves from the server's IP.

## Server setup (one script)

Upload `setup.sh` to a fresh Ubuntu/Debian server and run it:

```bash
sudo bash setup.sh
```

It installs dependencies, writes the server code, generates a self-signed TLS
cert, creates a config with fresh random credentials, installs a systemd
service (`rdpclip`), starts it, and prints the client settings to use.

Manage it with `systemctl status rdpclip` and `journalctl -u rdpclip -f`.

## Client (your PC)

Needs Python 3 and `pip install aardwolf asn1tools`. Copy
`clip_sender.example.json` to `clip_sender.json` and fill in the host and the
credentials `setup.sh` printed.

**Tunnel (SOCKS5 proxy, server as exit):**

```bash
python socks_tunnel.py            # SOCKS5 on 127.0.0.1:1080, pool of 4 sessions
python socks_tunnel.py 1080 1     # single session
```

Point your browser's SOCKS5 host at `127.0.0.1:1080`. Verify the exit IP:

```bash
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

**Clipboard (text box + Send, file transfer both ways):**

```bash
python clip_sender.py             # GUI
python clip_sender.py --send "hi" # one-shot from the shell
```

## Files

| File | Runs on | What it is |
|------|---------|------------|
| `rdpclip_server.py` | server | the RDP server: handshake, clipboard, tunnel |
| `setup.sh` | server | one-shot installer (embeds the server) |
| `socks_tunnel.py` | PC | SOCKS5 front end + session pool |
| `rdp_tunnel_channel.py` | PC | the custom tunnel virtual channel (aardwolf) |
| `clip_sender.py` | PC | clipboard GUI / CLI |

## How the tunnel is (and isn't) parallel

Streams are multiplexed over one virtual channel per RDP session. The client
opens a **pool** of sessions and spreads new streams across them, so many
connections (a web page's resources) run genuinely in parallel. But a *single*
stream — one big download, one video — is pinned to one session and capped at
that one connection's throughput; TCP ordering means you can't split one stream
across sessions without a reassembly layer. So pooling speeds up browsing, not a
single video stream.

## Notes / limits

- TLS only, no NLA/CredSSP — so `mstsc` and the iPad Windows App can't connect;
  the client here (aardwolf-based) can.
- One ordered channel per session means head-of-line blocking under load.
- Throughput is modest (single-digit Mbps per stream) — fine for browsing,
  text, files; marginal for high-bitrate live video.
