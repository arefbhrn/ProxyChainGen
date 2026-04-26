#!/usr/bin/env python3
"""ProxyChainGen GUI — paste URI or JSON to chain V2Ray/Xray proxies."""

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import json
import base64
import urllib.parse
import re

# ---------------------------------------------------------------------------
# URI parsers
# ---------------------------------------------------------------------------

def _b64pad(s): return s + '=' * (-len(s) % 4)


def parse_vmess(uri):
    try:
        c = json.loads(base64.b64decode(_b64pad(uri[8:])))
    except Exception as e:
        raise ValueError(f"Invalid vmess URI: {e}")
    return {
        "type": "vmess", "remark": c.get("ps", "vmess"),
        "address": c.get("add", ""), "port": int(c.get("port", 443)),
        "uuid": c.get("id", ""), "alterId": int(c.get("aid", 0)),
        "security": c.get("scy", "auto"), "network": c.get("net", "tcp"),
        "tls": c.get("tls", ""), "sni": c.get("sni", c.get("host", "")),
        "path": c.get("path", ""), "host": c.get("host", ""),
        "alpn": c.get("alpn", ""), "fp": c.get("fp", ""),
    }


def parse_vless(uri):
    p = urllib.parse.urlparse(uri)
    q = urllib.parse.parse_qs(p.query)
    def q1(k, d=""): return q.get(k, [d])[0]
    return {
        "type": "vless", "remark": urllib.parse.unquote(p.fragment or "vless"),
        "uuid": p.username or "", "address": p.hostname or "", "port": p.port or 443,
        "encryption": q1("encryption", "none"), "flow": q1("flow"),
        "network": q1("type", "tcp"), "security": q1("security", "none"),
        "sni": q1("sni"), "fp": q1("fp"), "path": q1("path"), "host": q1("host"),
        "serviceName": q1("serviceName"), "pbk": q1("pbk"),
        "sid": q1("sid"), "spx": q1("spx"), "alpn": q1("alpn"),
    }


def parse_trojan(uri):
    p = urllib.parse.urlparse(uri)
    q = urllib.parse.parse_qs(p.query)
    def q1(k, d=""): return q.get(k, [d])[0]
    return {
        "type": "trojan", "remark": urllib.parse.unquote(p.fragment or "trojan"),
        "password": urllib.parse.unquote(p.username or ""),
        "address": p.hostname or "", "port": p.port or 443,
        "network": q1("type", "tcp"), "security": q1("security", "tls"),
        "sni": q1("sni", p.hostname or ""), "fp": q1("fp"),
        "path": q1("path"), "host": q1("host"),
        "serviceName": q1("serviceName"), "alpn": q1("alpn"),
    }


def parse_ss(uri):
    p = urllib.parse.urlparse(uri)
    remark = urllib.parse.unquote(p.fragment or "shadowsocks")
    if p.hostname:
        try:
            ui = base64.b64decode(_b64pad(p.username)).decode()
            method, password = ui.split(':', 1)
        except Exception:
            method = urllib.parse.unquote(p.username or "")
            password = urllib.parse.unquote(p.password or "")
        return {"type": "shadowsocks", "remark": remark,
                "method": method, "password": password,
                "address": p.hostname, "port": p.port or 443}
    else:
        b64 = uri[5:].split('#')[0]
        decoded = base64.b64decode(_b64pad(b64)).decode()
        m = re.match(r'(.+?):(.+)@(.+):(\d+)', decoded)
        if not m: raise ValueError("Cannot parse ss URI")
        return {"type": "shadowsocks", "remark": remark,
                "method": m.group(1), "password": m.group(2),
                "address": m.group(3), "port": int(m.group(4))}


def parse_uri(uri):
    uri = uri.strip()
    if   uri.startswith("vmess://"):  return parse_vmess(uri)
    elif uri.startswith("vless://"):  return parse_vless(uri)
    elif uri.startswith("trojan://"): return parse_trojan(uri)
    elif uri.startswith("ss://"):     return parse_ss(uri)
    else: raise ValueError(f"Unsupported scheme: {uri[:40]}")


# ---------------------------------------------------------------------------
# URI → minimal V2Ray outbound
# ---------------------------------------------------------------------------

def _stream(cfg):
    network  = cfg.get("network", "tcp")
    security = cfg.get("security", cfg.get("tls", ""))
    s = {"network": network}
    if security == "reality":
        s["security"] = "reality"
        s["realitySettings"] = {
            "serverName": cfg.get("sni", ""), "fingerprint": cfg.get("fp", "chrome"),
            "publicKey": cfg.get("pbk", ""), "shortId": cfg.get("sid", ""),
            "spiderX": cfg.get("spx", "/"),
        }
    elif security == "tls" or cfg.get("tls") == "tls":
        s["security"] = "tls"
        tls = {}
        if cfg.get("sni"):  tls["serverName"]  = cfg["sni"]
        if cfg.get("fp"):   tls["fingerprint"] = cfg["fp"]
        if cfg.get("alpn"): tls["alpn"] = [a.strip() for a in cfg["alpn"].split(",") if a.strip()]
        s["tlsSettings"] = tls
    if network == "ws":
        ws = {"path": cfg.get("path", "/")}
        if cfg.get("host"): ws["headers"] = {"Host": cfg["host"]}
        s["wsSettings"] = ws
    elif network == "grpc":
        s["grpcSettings"] = {"serviceName": cfg.get("serviceName", cfg.get("path", ""))}
    elif network in ("h2", "http"):
        h2 = {"path": cfg.get("path", "/")}
        if cfg.get("host"): h2["host"] = [h.strip() for h in cfg["host"].split(",")]
        s["httpSettings"] = h2
    return s


def uri_cfg_to_outbound(cfg, tag):
    t = cfg["type"]
    stream = _stream(cfg)
    if t == "vmess":
        return {"tag": tag, "protocol": "vmess",
                "settings": {"vnext": [{"address": cfg["address"], "port": cfg["port"],
                    "users": [{"id": cfg["uuid"], "alterId": cfg.get("alterId", 0),
                               "security": cfg.get("security", "auto")}]}]},
                "streamSettings": stream}
    elif t == "vless":
        user = {"id": cfg["uuid"], "encryption": cfg.get("encryption", "none")}
        if cfg.get("flow"): user["flow"] = cfg["flow"]
        return {"tag": tag, "protocol": "vless",
                "settings": {"vnext": [{"address": cfg["address"], "port": cfg["port"],
                    "users": [user]}]},
                "streamSettings": stream}
    elif t == "trojan":
        return {"tag": tag, "protocol": "trojan",
                "settings": {"servers": [{"address": cfg["address"], "port": cfg["port"],
                    "password": cfg["password"]}]},
                "streamSettings": stream}
    elif t == "shadowsocks":
        return {"tag": tag, "protocol": "shadowsocks",
                "settings": {"servers": [{"address": cfg["address"], "port": cfg["port"],
                    "method": cfg["method"], "password": cfg["password"], "level": 0}]},
                "streamSettings": {"network": "tcp"}}
    raise ValueError(f"Unknown type: {t}")


# ---------------------------------------------------------------------------
# JSON config parser — extract first proxy outbound
# ---------------------------------------------------------------------------

SKIP = {"freedom", "blackhole", "dns", "loopback"}


def extract_outbound(cfg_json: dict, label: str) -> dict:
    for ob in cfg_json.get("outbounds", []):
        if ob.get("protocol") not in SKIP:
            return ob
    raise ValueError(f"No proxy outbound in {label}")


# ---------------------------------------------------------------------------
# Entry normalisation
# Each entry: {"label": str, "outbound": dict (ready V2Ray outbound object)}
# ---------------------------------------------------------------------------

def entry_from_uri(uri_text: str) -> list[dict]:
    entries = []
    for line in uri_text.splitlines():
        line = line.strip()
        if not line: continue
        parsed = parse_uri(line)
        label  = f"{parsed['type']}  {parsed.get('remark','')}"
        # outbound built later with proper tag; store parsed cfg for now
        entries.append({"label": label, "parsed": parsed, "source": "uri"})
    return entries


def entry_from_json(text: str) -> dict:
    cfg = json.loads(text)
    if "outbounds" in cfg:
        ob = extract_outbound(cfg, "pasted JSON")
        proto = ob.get("protocol", "?")
        label = f"{proto}  (from config JSON)"
    elif "protocol" in cfg:
        ob = cfg
        label = f"{cfg.get('protocol','?')}  (outbound JSON)"
    else:
        raise ValueError("Paste a full V2Ray config or a single outbound object")
    return {"label": label, "outbound": ob, "source": "json"}


# ---------------------------------------------------------------------------
# Chain builder
# ---------------------------------------------------------------------------

def build_chain(entries: list[dict], socks_port: int = 1080) -> dict:
    if len(entries) < 2:
        raise ValueError("Need at least 2 entries")

    outbounds = []
    for i, e in enumerate(entries):
        tag = f"proxy-{chr(ord('a') + i)}"
        if e["source"] == "uri":
            ob = uri_cfg_to_outbound(e["parsed"], tag)
        else:
            ob = dict(e["outbound"])
            ob["tag"] = tag
        outbounds.append(ob)

    # proxy-b uses proxy-a as transport → traffic: local → A → B → internet
    for i in range(1, len(outbounds)):
        prev_ob = outbounds[i - 1]
        prev_sec = prev_ob.get("streamSettings", {}).get("security", "")
        transport_layer = prev_sec in ("tls", "reality")
        outbounds[i]["proxySettings"] = {
            "tag": prev_ob["tag"],
            "transportLayer": transport_layer,
        }

    last_tag = outbounds[-1]["tag"]

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks", "port": socks_port, "listen": "127.0.0.1",
             "protocol": "socks", "settings": {"auth": "noauth", "udp": True},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}},
            {"tag": "http", "port": socks_port + 1, "listen": "127.0.0.1",
             "protocol": "http"},
        ],
        "outbounds": [outbounds[-1]] + outbounds[:-1] + [
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block",  "protocol": "blackhole", "settings": {}},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "inboundTag": ["socks", "http"], "outboundTag": last_tag}
            ],
        },
    }


# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------

BG    = "#1e1e2e"
PANEL = "#24273a"
ACCENT= "#89b4fa"
FG    = "#cdd6f4"
MUTED = "#6c7086"
GREEN = "#a6e3a1"
RED   = "#f38ba8"
ENTRY = "#313244"

MONO  = ("Courier New", 10)
UI    = ("Helvetica", 11)
BOLD  = ("Helvetica", 11, "bold")
TITLE = ("Helvetica", 15, "bold")


def flat_btn(parent, text, cmd, bg=PANEL, fg=FG, **kw):
    kw.setdefault("font", UI)
    return tk.Button(parent, text=text, command=cmd,
                     bg=bg, fg=fg, activebackground=ENTRY, activeforeground=fg,
                     relief="flat", bd=0, padx=12, pady=5, **kw)


# ---------------------------------------------------------------------------
# Paste dialog  (URI or JSON)
# ---------------------------------------------------------------------------

class PasteDialog(tk.Toplevel):
    def __init__(self, parent, mode: str):
        super().__init__(parent)
        self.result = None
        self.grab_set()
        self.configure(bg=BG)
        self.resizable(True, True)

        if mode == "uri":
            self.title("Add — Paste URI")
            hint = "Paste one or more URIs (vmess:// · vless:// · trojan:// · ss://):"
            h = 6
        else:
            self.title("Add — Paste JSON")
            hint = "Paste a full V2Ray config JSON  —or—  a single outbound object:"
            h = 18

        tk.Label(self, text=hint, bg=BG, fg=FG, font=UI,
                 wraplength=500, justify="left").pack(anchor="w", padx=14, pady=(12, 4))

        self.txt = scrolledtext.ScrolledText(
            self, height=h, wrap="word" if mode == "uri" else "none",
            bg=ENTRY, fg=FG, insertbackground=FG,
            font=MONO, relief="flat", borderwidth=6,
        )
        self.txt.pack(fill="both", expand=True, padx=14, pady=4)

        br = tk.Frame(self, bg=BG)
        br.pack(fill="x", padx=14, pady=(4, 12))
        flat_btn(br, "Cancel", self.destroy, fg=MUTED).pack(side="right", padx=(6, 0))
        flat_btn(br, "  Add  ", self._ok, bg=ACCENT, fg=BG, font=BOLD).pack(side="right")

        self.geometry("540x260" if mode == "uri" else "560x460")
        self.txt.focus()
        self.bind("<Escape>", lambda _: self.destroy())

    def _ok(self):
        self.result = self.txt.get("1.0", tk.END).strip()
        self.destroy()


# ---------------------------------------------------------------------------
# Main App
# ---------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ProxyChainGen")
        self.configure(bg=BG)
        self.geometry("960x660")
        self.minsize(680, 480)
        self.entries: list[dict] = []
        self._build()

    def _build(self):
        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill="x", padx=16, pady=(12, 6))
        tk.Label(hdr, text="ProxyChainGen", bg=BG, fg=ACCENT, font=TITLE).pack(side="left")
        tk.Label(hdr, text="Client → A → B → … → Internet",
                 bg=BG, fg=MUTED, font=UI).pack(side="left", padx=12)

        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=10, pady=4)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        # ---- Left ----
        left = tk.Frame(body, bg=BG)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        left.rowconfigure(1, weight=1)
        left.columnconfigure(0, weight=1)

        tk.Label(left, text="Proxy Chain  (top = first hop)",
                 bg=BG, fg=FG, font=BOLD, anchor="w").grid(row=0, column=0, sticky="w", pady=(0, 4))

        lf = tk.Frame(left, bg=PANEL)
        lf.grid(row=1, column=0, sticky="nsew")
        lf.rowconfigure(0, weight=1)
        lf.columnconfigure(0, weight=1)

        self.lb = tk.Listbox(lf, bg=PANEL, fg=FG,
                             selectbackground=ACCENT, selectforeground=BG,
                             activestyle="none", font=MONO,
                             borderwidth=0, highlightthickness=0, relief="flat")
        sb = tk.Scrollbar(lf, orient="vertical", command=self.lb.yview,
                          bg=PANEL, troughcolor=PANEL, relief="flat", width=8)
        self.lb.configure(yscrollcommand=sb.set)
        sb.grid(row=0, column=1, sticky="ns")
        self.lb.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)

        br = tk.Frame(left, bg=BG)
        br.grid(row=2, column=0, sticky="ew", pady=6)
        flat_btn(br, "+ URI",  lambda: self._add("uri"),  bg=ACCENT, fg=BG).pack(side="left", padx=(0, 4))
        flat_btn(br, "+ JSON", lambda: self._add("json")).pack(side="left", padx=(0, 8))
        flat_btn(br, "↑", self.move_up).pack(side="left", padx=(0, 2))
        flat_btn(br, "↓", self.move_down).pack(side="left", padx=(0, 8))
        flat_btn(br, "✕", self.remove, fg=RED).pack(side="left")

        self.status_var = tk.StringVar(value="Add at least 2 configs")
        tk.Label(left, textvariable=self.status_var, bg=BG, fg=MUTED,
                 font=UI, anchor="w").grid(row=3, column=0, sticky="w")

        # Port row
        pr = tk.Frame(left, bg=BG)
        pr.grid(row=4, column=0, sticky="ew", pady=(8, 4))
        tk.Label(pr, text="SOCKS5 port:", bg=BG, fg=FG, font=UI).pack(side="left")
        self.port_var = tk.StringVar(value="1080")
        tk.Entry(pr, textvariable=self.port_var, width=6,
                 bg=ENTRY, fg=FG, insertbackground=FG,
                 font=MONO, relief="flat", bd=4).pack(side="left", padx=6)
        tk.Label(pr, text="HTTP = port+1", bg=BG, fg=MUTED, font=UI).pack(side="left")

        flat_btn(left, "⚡  Generate Chain", self.generate,
                 bg=GREEN, fg=BG, font=BOLD).grid(row=5, column=0, sticky="ew", pady=(4, 0))

        # ---- Right ----
        right = tk.Frame(body, bg=BG)
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        oh = tk.Frame(right, bg=BG)
        oh.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        tk.Label(oh, text="Output JSON", bg=BG, fg=FG, font=BOLD).pack(side="left")
        self.out_status = tk.Label(oh, text="", bg=BG, fg=MUTED, font=UI)
        self.out_status.pack(side="left", padx=8)

        self.output = scrolledtext.ScrolledText(
            right, wrap="none", bg=PANEL, fg=FG, insertbackground=FG,
            font=MONO, relief="flat", borderwidth=0)
        self.output.grid(row=1, column=0, sticky="nsew")

        obr = tk.Frame(right, bg=BG)
        obr.grid(row=2, column=0, sticky="ew", pady=6)
        flat_btn(obr, "Copy", self.copy, bg=ACCENT, fg=BG).pack(side="left", padx=(0, 6))
        flat_btn(obr, "Save as…", self.save).pack(side="left")

    # ------------------------------------------------------------------

    def _refresh(self):
        self.lb.delete(0, tk.END)
        for i, e in enumerate(self.entries):
            self.lb.insert(tk.END, f"  [{i+1}]  {e['label']}")
        n = len(self.entries)
        self.status_var.set(
            "Add at least 2 configs" if n == 0 else
            "Add 1 more config"       if n == 1 else
            f"{n} configs · {n}-hop chain ready"
        )

    def _add(self, mode: str):
        dlg = PasteDialog(self, mode)
        self.wait_window(dlg)
        if not dlg.result:
            return
        if mode == "uri":
            try:
                new = entry_from_uri(dlg.result)
                if not new:
                    messagebox.showerror("Empty", "No valid URIs found.", parent=self)
                    return
                self.entries.extend(new)
            except Exception as e:
                messagebox.showerror("Parse Error", str(e), parent=self)
        else:
            try:
                self.entries.append(entry_from_json(dlg.result))
            except Exception as e:
                messagebox.showerror("Parse Error", str(e), parent=self)
        self._refresh()

    def move_up(self):
        sel = self.lb.curselection()
        if not sel or sel[0] == 0: return
        i = sel[0]
        self.entries[i-1], self.entries[i] = self.entries[i], self.entries[i-1]
        self._refresh(); self.lb.selection_set(i-1)

    def move_down(self):
        sel = self.lb.curselection()
        if not sel or sel[0] >= len(self.entries)-1: return
        i = sel[0]
        self.entries[i], self.entries[i+1] = self.entries[i+1], self.entries[i]
        self._refresh(); self.lb.selection_set(i+1)

    def remove(self):
        sel = self.lb.curselection()
        if not sel: return
        self.entries.pop(sel[0])
        self._refresh()

    def generate(self):
        if len(self.entries) < 2:
            messagebox.showwarning("Not enough", "Add at least 2 configs.", parent=self)
            return
        try:
            port   = int(self.port_var.get())
            result = build_chain(self.entries, port)
            text   = json.dumps(result, indent=2, ensure_ascii=False)
            self.output.delete("1.0", tk.END)
            self.output.insert("1.0", text)
            chain = " → ".join(f"proxy-{chr(ord('a')+i)}" for i in range(len(self.entries)))
            self.out_status.config(text=f"✓  {chain} → Internet  ·  SOCKS5 :{port}", fg=GREEN)
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self)

    def copy(self):
        text = self.output.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("Empty", "Generate first.", parent=self); return
        self.clipboard_clear(); self.clipboard_append(text)
        self.out_status.config(text="Copied!", fg=ACCENT)

    def save(self):
        text = self.output.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("Empty", "Generate first.", parent=self); return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json"), ("All", "*.*")])
        if not path: return
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        self.out_status.config(text=f"Saved → {path}", fg=GREEN)


if __name__ == "__main__":
    App().mainloop()
