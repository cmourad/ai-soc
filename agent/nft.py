#!/usr/bin/env python3
"""The single writer of the nftables set.

The console never runs nft. One writer means one Guard, one timeout ladder and
one audit trail; a second writer with its own idea of what may be blocked is how
a UI ends up firewalling the default gateway. Every element carries a kernel-side
timeout, so a block expires even if this process dies holding it.
"""

import ipaddress
import json
import logging

from guard import _cmd

log = logging.getLogger("aisoc")

NFT_SETUP = [
    ["nft", "add", "table", "inet", "aisoc"],
    ["nft", "add", "set", "inet", "aisoc", "blocked",
     "{ type ipv4_addr; flags timeout; }"],
    ["nft", "add", "set", "inet", "aisoc", "blocked6",
     "{ type ipv6_addr; flags timeout; }"],
    ["nft", "add", "chain", "inet", "aisoc", "input",
     "{ type filter hook input priority -10; policy accept; }"],
    ["nft", "add", "chain", "inet", "aisoc", "output",
     "{ type filter hook output priority -10; policy accept; }"],
]
NFT_RULES = [
    ("input", "ip saddr @blocked drop"),
    ("input", "ip6 saddr @blocked6 drop"),
    ("output", "ip daddr @blocked drop"),
    ("output", "ip6 daddr @blocked6 drop"),
]


def ensure_nft():
    for args in NFT_SETUP:
        r = _cmd(args)
        if r.returncode != 0 and "File exists" not in r.stderr:
            raise RuntimeError(f"nft setup failed: {' '.join(args)}: {r.stderr.strip()}")
    listing = _cmd(["nft", "list", "table", "inet", "aisoc"]).stdout
    for chain, rule in NFT_RULES:
        if rule not in listing:
            r = _cmd(["nft", "add", "rule", "inet", "aisoc", chain] + rule.split())
            if r.returncode != 0:
                raise RuntimeError(f"nft rule failed: {rule}: {r.stderr.strip()}")


def _set_for(ip):
    return "blocked6" if ipaddress.ip_address(ip).version == 6 else "blocked"


def nft_block(ip, seconds):
    s = _set_for(ip)
    _cmd(["nft", "delete", "element", "inet", "aisoc", s, f"{{ {ip} }}"])
    r = _cmd(["nft", "add", "element", "inet", "aisoc", s,
              f"{{ {ip} timeout {seconds}s }}"])
    return r.returncode == 0, r.stderr.strip()


def nft_unblock(ip):
    r = _cmd(["nft", "delete", "element", "inet", "aisoc", _set_for(ip), f"{{ {ip} }}"])
    return r.returncode == 0, r.stderr.strip()


def nft_blocked():
    """Current set members with the lifetime left on each.

    nft's JSON writes an element either as a bare address (no timeout) or as
    {"elem": {"val": ..., "timeout": ..., "expires": ...}}, so both shapes are
    handled — a set that predates the timeout flag would otherwise read empty.
    """
    out = []
    for name in ("blocked", "blocked6"):
        r = _cmd(["nft", "-j", "list", "set", "inet", "aisoc", name])
        if r.returncode != 0:
            continue
        try:
            doc = json.loads(r.stdout)
        except ValueError:
            log.warning("nft -j returned unparseable output for set %s", name)
            continue
        for node in doc.get("nftables", []):
            for raw in node.get("set", {}).get("elem", []) or []:
                elem = raw.get("elem", raw) if isinstance(raw, dict) else raw
                if isinstance(elem, dict):
                    val, timeout, expires = (elem.get("val"), elem.get("timeout"),
                                             elem.get("expires"))
                else:
                    val, timeout, expires = elem, None, None
                if isinstance(val, str):
                    out.append({"ip": val, "set": name,
                                "timeout": timeout, "expires": expires})
    return out
