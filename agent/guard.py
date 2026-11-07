#!/usr/bin/env python3
"""What the agent must never block, whatever the model says.

This is the hard safety boundary of the whole system. A verdict is a
recommendation; this module is the veto, and it is deliberately separate from
the code that writes the firewall so that "may I block this" and "block it" can
never collapse into one step.
"""

import ipaddress
import json
import re
import subprocess

from config import ALLOWLIST

def _cmd(args):
    return subprocess.run(args, capture_output=True, text=True)


def own_ips():
    ips = set()
    out = _cmd(["ip", "-j", "addr"]).stdout
    for iface in json.loads(out or "[]"):
        for a in iface.get("addr_info", []):
            ips.add(a["local"])
    return ips


def gateway_ips():
    ips = set()
    for line in _cmd(["ip", "route"]).stdout.splitlines():
        m = re.match(r"default via (\S+)", line)
        if m:
            ips.add(m.group(1))
    return ips


def nameserver_ips():
    ips = set()
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                m = re.match(r"nameserver\s+(\S+)", line)
                if m:
                    ips.add(m.group(1))
    except OSError:
        pass
    return ips


def allowlist_ips():
    ips = set()
    try:
        with open(ALLOWLIST) as f:
            for line in f:
                line = line.split("#")[0].strip()
                if line:
                    ips.add(line)
    except OSError:
        pass
    return ips


class Guard:
    """Everything the agent must never block, regardless of LLM output."""

    def __init__(self):
        self.static = {"0.0.0.0", "255.255.255.255"}
        self.refresh()

    def refresh(self):
        self.own = own_ips()
        self.protected = (
            self.static | self.own | gateway_ips() | nameserver_ips() | allowlist_ips()
        )

    def shape_refused(self, ip):
        """Refused for what the address is, before any list is consulted."""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if a.is_loopback or a.is_multicast or a.is_link_local or a.is_unspecified:
            return True
        # docker bridge space — blocking it breaks local containers, never useful
        return a.version == 4 and a in ipaddress.ip_network("172.16.0.0/12")

    def is_protected(self, ip):
        return ip in self.protected or self.shape_refused(ip)

    def listed(self):
        """The protected entries worth showing: every address that is refused by
        shape is refused whether or not it appears here, and this host's veth
        sprawl contributes a hundred link-local addresses that say nothing."""
        return sorted(ip for ip in self.protected if not self.shape_refused(ip))
