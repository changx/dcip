#!/usr/bin/env python3
"""Write out/hosting-ipv4.txt / -ipv6.txt = combined - relay - vpn - meta.

Run after china.py, which adds China carrier overseas space to combined.
hosting is the part of combined that is neither a privacy egress (iCloud Private
Relay, consumer VPN) nor Meta: servers, clouds, proxies and crawlers.
"""
import ipaddress
from pathlib import Path

OUT = Path(__file__).resolve().parent / "out"


def intervals(stem, v):
    nets = ipaddress.collapse_addresses(
        ipaddress.ip_network(x) for x in (OUT / f"{stem}-ipv{v}.txt").read_text().split())
    return [(int(n.network_address), int(n.broadcast_address)) for n in nets]


def subtract(base, cut):
    """Both inputs sorted and non-overlapping; returns base minus cut."""
    out, j = [], 0
    for lo, hi in base:
        while j < len(cut) and cut[j][1] < lo:
            j += 1
        k = j
        while k < len(cut) and cut[k][0] <= hi:
            if cut[k][0] > lo:
                out.append((lo, cut[k][0] - 1))
            lo = max(lo, cut[k][1] + 1)
            if lo > hi:
                break
            k += 1
        if lo <= hi:
            out.append((lo, hi))
    return out


for v in (4, 6):
    cls = ipaddress.IPv4Address if v == 4 else ipaddress.IPv6Address
    cut = []
    for stem in ("relay", "vpn", "meta"):
        cut += intervals(stem, v)
    cut = [(int(n.network_address), int(n.broadcast_address)) for n in ipaddress.collapse_addresses(
        n for lo, hi in cut for n in ipaddress.summarize_address_range(cls(lo), cls(hi)))]
    rest = subtract(intervals("combined", v), cut)
    nets = ipaddress.collapse_addresses(
        n for lo, hi in rest for n in ipaddress.summarize_address_range(cls(lo), cls(hi)))
    (OUT / f"hosting-ipv{v}.txt").write_text("".join(f"{n}\n" for n in nets))
    print(f"hosting-ipv{v}: {len(rest)} ranges")
