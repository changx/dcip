#!/usr/bin/env python3
"""Coverage check: share of each ASN's announced IPv4 space that out/combined-ipv4.txt covers."""
import bisect, gzip, ipaddress, re
from pathlib import Path
R = Path(__file__).resolve().parent
comb = [ipaddress.ip_network(x) for x in (R / "out/combined-ipv4.txt").read_text().split()]
S = [int(n.network_address) for n in comb]; E = [int(n.broadcast_address) for n in comb]
def covered(n):
    lo, hi = int(n.network_address), int(n.broadcast_address)
    i, c = max(bisect.bisect_right(S, lo) - 1, 0), 0
    while i < len(S) and S[i] <= hi:
        if E[i] >= lo: c += min(hi, E[i]) - max(lo, S[i]) + 1
        i += 1
    return c
own = {}
with gzip.open(R / "data/rv4.pfx2as.gz", "rt") as f:
    for l in f:
        p, L, o = l.split()
        for x in re.split(r"[_,]", o):
            if x.isdigit(): own.setdefault(int(x), []).append(ipaddress.ip_network(f"{p}/{L}"))
TESTS = {
    "IDC/VPS (expect high)": [38136, 983, 906, 132110, 25820, 58658, 40065, 35916, 54600,
                              21859, 62468, 36352, 199524, 140096],
    "residential/mobile (expect ~0)": [7922, 701, 7018, 20115, 21928, 4134, 4837, 9808, 3320,
                                       2856, 4766, 17676, 4713, 9318, 3462, 22773],
}
for k, v in TESTS.items():
    print("==", k)
    for a in v:
        nets = list(ipaddress.collapse_addresses(own.get(a, [])))
        tot = sum(n.num_addresses for n in nets)
        print(f"  AS{a}: " + (f"{sum(covered(n) for n in nets)/tot:6.1%} of {tot//256} /24s" if tot else "no prefixes"))
