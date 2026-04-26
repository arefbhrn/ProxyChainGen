# ProxyChainGen

Chain multiple V2Ray/Xray proxies into a single config file.  
**Flow:** `Client → A → B → … → Internet`

## What it does

Takes 2+ proxy configs (by URI or JSON) and produces one V2Ray/Xray JSON that routes traffic through all of them in sequence. The last proxy exits to the internet; each earlier proxy acts as transport for the next.

`transportLayer` is set automatically based on whether the upstream uses TLS/Reality.

---

## Tools

| File | What |
|------|------|
| `main.py` | Tkinter GUI — paste URIs or JSONs, reorder, generate, copy/save |
| `chain.py` | CLI — chain 2+ existing V2Ray JSON files |

---

## Requirements

Python 3.10+ (stdlib only — `tkinter`, `json`, `base64`, `urllib`).

---

## GUI (`main.py`)

```bash
python main.py
```

1. Click **+ URI** to paste one or more share links (`vmess://`, `vless://`, `trojan://`, `ss://`)
2. Click **+ JSON** to paste a full V2Ray config or a single outbound object
3. Reorder with ↑ / ↓ (top = first hop)
4. Set SOCKS5 port (HTTP proxy = port + 1)
5. Click **⚡ Generate Chain** → copy or save the output JSON

### Supported protocols

| Protocol | URI scheme | Transport | Security |
|----------|-----------|-----------|----------|
| VMess | `vmess://` | tcp, ws, grpc, h2 | tls, reality |
| VLESS | `vless://` | tcp, ws, grpc, h2 | tls, reality |
| Trojan | `trojan://` | tcp, ws, grpc, h2 | tls, reality |
| Shadowsocks | `ss://` | tcp only | none |

Shadowsocks is always emitted with `"streamSettings": {"network": "tcp"}` — no TLS/Reality/transport variants.  
`transportLayer` in `proxySettings` is `true` only when the upstream hop uses `tls` or `reality`; Shadowsocks hops always produce `transportLayer: false`.

---

## CLI (`chain.py`)

Chain two or more existing V2Ray/Xray JSON config files:

```bash
# Two hops
python chain.py a.json b.json output.json

# Three hops
python chain.py a.json b.json c.json output.json
```

- Reads the first non-utility outbound from each file (skips `freedom`, `blackhole`, `dns`, `loopback`)
- Tags them `proxy-a`, `proxy-b`, `proxy-c`, …
- Wires `proxySettings` so each hop tunnels through the previous one
- Inherits inbounds, DNS, and routing from the first config
- Fixes any routing rules pointing to the old outbound tag
- Adds a catch-all `tcp,udp` rule if one is missing

---

## Output format

Both tools produce a standard V2Ray/Xray JSON with:

```
inbounds:  SOCKS5 on 127.0.0.1:<port>  +  HTTP on 127.0.0.1:<port+1>
outbounds: proxy-a, proxy-b, …, direct, block
routing:   all traffic → last proxy in chain
```

Load the output JSON directly in V2Ray, Xray, or any compatible core.

---

## Example — two VLESS hops

```
vless://uuid1@server1:443?type=ws&security=tls&sni=server1.example.com#Hop-A
vless://uuid2@server2:443?type=grpc&security=reality&pbk=...&sid=...#Hop-B
```

Paste both into the GUI → Generate → load result in Xray.  
Traffic path: `SOCKS5 :1080 → Hop-A (WS+TLS) → Hop-B (gRPC+Reality) → Internet`
