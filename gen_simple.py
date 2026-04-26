#!/usr/bin/env python3
"""
Chain 2+ V2Ray/Xray JSON configs.

Usage:
    python chain.py a.json b.json output.json

Flow: Client -> A -> B -> Internet
"""

import json
import sys

def chain_configs(config_a_path: str, config_b_path: str, output_path: str):
    with open(config_a_path) as f:
        config_a = json.load(f)
    with open(config_b_path) as f:
        config_b = json.load(f)

    # Extract first outbound from each config
    outbound_a = next(o for o in config_a["outbounds"] if o.get("tag") == "proxy" or o.get("protocol") == "vless")
    outbound_b = next(o for o in config_b["outbounds"] if o.get("tag") == "proxy" or o.get("protocol") == "vless")

    outbound_a["tag"] = "proxy-a"
    outbound_b["tag"] = "proxy-b"

    # Chain: Client -> A -> B -> Internet
    outbound_b["proxySettings"] = {
        "tag": "proxy-a",
        "transportLayer": True
    }

    # Build final config based on config_a structure
    result = dict(config_a)
    result["outbounds"] = [
        outbound_b,
        outbound_a,
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "block"}
    ]

    # Fix routing to point to proxy-b as default
    for rule in result["routing"]["rules"]:
        if rule.get("outboundTag") == "proxy":
            rule["outboundTag"] = "proxy-b"

    # Add catch-all rule if not present
    has_catchall = any(
        r.get("network") == "tcp,udp" for r in result["routing"]["rules"]
    )
    if not has_catchall:
        result["routing"]["rules"].append({
            "type": "field",
            "network": "tcp,udp",
            "outboundTag": "proxy-b"
        })

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Chained config saved to: {output_path}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python chain.py <config_a> <config_b> <output>")
        sys.exit(1)

    chain_configs(sys.argv[1], sys.argv[2], sys.argv[3])