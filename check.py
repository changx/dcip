#!/usr/bin/env python3
"""Usage: check.py <ip-or-cidr> [...]  -> which output lists cover or overlap it."""
import ipaddress, sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / "out"
for q in sys.argv[1:]:
    t = ipaddress.ip_network(q, strict=False)
    print(f"== {t}")
    for f in sorted(OUT.glob(f"*-ipv{t.version}.txt")):
        for line in f.read_text().split():
            n = ipaddress.ip_network(line)
            if n.overlaps(t):
                kind = "covers" if t.subnet_of(n) else "overlaps"
                print(f"  {f.name}: {kind} {n}")
