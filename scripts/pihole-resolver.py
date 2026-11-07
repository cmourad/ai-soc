#!/usr/bin/env python3
"""Point the host's systemd-resolved default route at the local Pi-hole."""

from __future__ import annotations

import json
import subprocess
import sys

WIFI_INTERFACE = "wlp7s0"
VPN_INTERFACE = "aisoc0"
RESOLVECTL = "/usr/bin/resolvectl"


def run(*args: str) -> None:
    subprocess.run(args, check=True, timeout=10)


def wifi_address() -> str:
    result = subprocess.run(
        ["/usr/sbin/ip", "-4", "-j", "address", "show", "dev", WIFI_INTERFACE],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    for interface in json.loads(result.stdout):
        for address in interface.get("addr_info", []):
            if address.get("family") == "inet" and address.get("scope") == "global":
                return str(address["local"])
    raise RuntimeError(f"{WIFI_INTERFACE} has no global IPv4 address")


def link_setting(kind: str, interface: str) -> list[str]:
    """`resolvectl dns|domain IFACE` prints `Link N (iface): a b c`, or nothing."""
    result = subprocess.run(
        [RESOLVECTL, kind, interface],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        return []
    _, _, values = result.stdout.strip().partition(":")
    return values.split()


def status() -> dict:
    try:
        expected = wifi_address()
    except Exception:
        expected = None
    dns = link_setting("dns", WIFI_INTERFACE)
    domains = link_setting("domain", WIFI_INTERFACE)
    vpn_dns = link_setting("dns", VPN_INTERFACE)
    return {
        "interface": WIFI_INTERFACE,
        "dns": dns,
        "domains": domains,
        "expected": expected,
        "vpn": {
            "interface": VPN_INTERFACE,
            "dns": vpn_dns,
            "domains": link_setting("domain", VPN_INTERFACE),
        },
        # The tunnel keeps its own ~. route, so ours only wins while the VPN
        # link carries no resolver of its own.
        "routed": bool(expected) and expected in dns and "~." in domains and not vpn_dns,
    }


def apply() -> None:
    address = wifi_address()
    # wg-quick installs the provider's DNS and a competing ~. route on the
    # tunnel. Clear that runtime state, then route all ordinary lookups to
    # Pi-hole on the link where its address is actually reachable.
    run(RESOLVECTL, "revert", VPN_INTERFACE)
    run(RESOLVECTL, "dns", WIFI_INTERFACE, address)
    run(RESOLVECTL, "domain", WIFI_INTERFACE, "~.")


def main() -> int:
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    if action == "apply":
        apply()
        return 0
    if action == "revert":
        run(RESOLVECTL, "revert", WIFI_INTERFACE)
        return 0
    if action == "status":
        print(json.dumps(status(), separators=(",", ":")))
        return 0
    print("usage: pihole-resolver.py apply|revert|status", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
