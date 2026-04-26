#!/usr/bin/env python3
"""
Chain 2+ V2Ray/Xray JSON configs.

Usage:
    python chain.py a.json b.json output.json
    python chain.py a.json b.json c.json output.json

Flow: Client -> A -> B -> ... -> Internet
"""

import json
import sys

SKIP_PROTOCOLS = {"freedom", "blackhole", "dns", "loopback"}


def first_proxy_outbound(config: dict, label: str) -> dict:
    for ob in config.get("outbounds", []):
        if ob.get("protocol") not in SKIP_PROTOCOLS:
            return ob
    raise ValueError(f"No proxy outbound found in {label}")


def chain_configs(input_paths: list[str], output_path: str):
    configs = []
    for path in input_paths:
        with open(path) as f:
            configs.append((path, json.load(f)))

    outbounds = []
    for i, (path, cfg) in enumerate(configs):
        ob = dict(first_proxy_outbound(cfg, path))
        ob["tag"] = f"proxy-{chr(ord('a') + i)}"  # proxy-a, proxy-b, proxy-c ...
        outbounds.append(ob)

    # Chain: outbound[i] (i > 0) uses outbound[i-1] as transport
    # Route to last outbound → traffic: A -> B -> ... -> internet
    for i in range(1, len(outbounds)):
        outbounds[i]["proxySettings"] = {
            "tag": outbounds[i - 1]["tag"],
            "transportLayer": True,
        }

    last_tag = outbounds[-1]["tag"]

    # Base structure from first config (inherits inbounds, dns, etc.)
    result = dict(configs[0][1])
    result["outbounds"] = outbounds + [
        {"protocol": "freedom",   "tag": "direct"},
        {"protocol": "blackhole", "tag": "block"},
    ]

    # Fix routing rules that pointed to the original proxy outbound
    routing = result.get("routing", {})
    for rule in routing.get("rules", []):
        if rule.get("outboundTag") not in {o["tag"] for o in result["outbounds"]}:
            rule["outboundTag"] = last_tag
    result["routing"] = routing

    # Ensure a catch-all rule exists
    rules = routing.get("rules", [])
    has_catchall = any(r.get("network") in ("tcp,udp", "udp,tcp") for r in rules)
    if not has_catchall:
        rules.append({
            "type": "field",
            "network": "tcp,udp",
            "outboundTag": last_tag,
        })
    routing["rules"] = rules

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    chain_str = " -> ".join(o["tag"] for o in outbounds) + " -> Internet"
    print(f"Chain:  Client -> {chain_str}")
    print(f"Saved:  {output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python chain.py a.json b.json [c.json ...] output.json")
        sys.exit(1)

    *inputs, output = sys.argv[1:]
    chain_configs(inputs, output)
