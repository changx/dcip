#!/usr/bin/env python3
"""Coverage check: share of each ASN's announced IPv4 space that an output list covers."""
import bisect, gzip, ipaddress, re
from pathlib import Path
R = Path(__file__).resolve().parent

own = {}
with gzip.open(R / "data/rv4.pfx2as.gz", "rt") as f:
    for l in f:
        p, L, o = l.split()
        for x in re.split(r"[_,]", o):
            if x.isdigit(): own.setdefault(int(x), []).append(ipaddress.ip_network(f"{p}/{L}"))

def loader(name):
    nets = [ipaddress.ip_network(x) for x in (R / "out" / name).read_text().split()]
    return [int(n.network_address) for n in nets], [int(n.broadcast_address) for n in nets]

def share(lst, a):
    S, E = lst
    nets = list(ipaddress.collapse_addresses(own.get(a, [])))
    tot = sum(n.num_addresses for n in nets)
    if not tot: return None
    c = 0
    for n in nets:
        lo, hi = int(n.network_address), int(n.broadcast_address)
        i = max(bisect.bisect_right(S, lo) - 1, 0)
        while i < len(S) and S[i] <= hi:
            if E[i] >= lo: c += min(hi, E[i]) - max(lo, S[i]) + 1
            i += 1
    return c / tot

# (list file, label, expectation, ASNs). "high" means >= 90 %, "low" means <= 5 %.
TESTS = [
    ("combined-ipv4.txt", "IDC/VPS", "high",
     [38136, 906, 132110, 25820, 40065, 35916, 54600, 21859, 62468, 36352, 199524, 140096, 23764, 58453]),
    ("combined-ipv4.txt", "residential/mobile", "low",
     [7922, 701, 7018, 20115, 21928, 4134, 4837, 9808, 3320, 2856, 4766, 17676, 4713, 3462, 9231]),
    ("china-compliance-ipv4.txt", "CN/HK/MO networks + Chinese groups abroad", "high",
     [4134, 4837, 9808, 9231, 4760, 10103, 45102, 132203, 134963, 150436, 23764, 58453]),
    ("china-compliance-ipv4.txt", "non-China networks", "low",
     [7922, 7018, 3320, 4766, 17676, 16509, 24940]),
    ("china-optimized-dc-ipv4.txt", "China-line IDCs", "high",
     [38136, 906, 25820, 40065, 54600, 35916, 21859]),
    ("china-optimized-dc-ipv4.txt", "hyperscalers / generic hosting", "low",
     [16509, 8075, 15169, 396982, 24940, 14061, 16276, 20473, 63949, 47583,
      32934, 63293, 199524, 49544, 34549]),
    ("combined-ipv4.txt", "Meta (Facebook, CDN)", "high", [32934, 63293]),
    ("meta-ipv4.txt", "Meta ASNs", "high", [32934, 63293, 54115]),
    ("meta-ipv4.txt", "non-Meta networks", "low", [16509, 15169, 8075, 7922, 4134]),
]
fails = 0
for fname, label, exp, asns in TESTS:
    lst = loader(fname)
    print(f"== {fname}: {label} (expect {exp})")
    for a in asns:
        s = share(lst, a)
        ok = s is None or (s >= 0.9 if exp == "high" else s <= 0.05)
        fails += not ok
        print(f"  {'ok ' if ok else 'BAD'} AS{a}: " + ("no prefixes" if s is None else f"{s:6.1%}"))
print(f"{fails} unexpected result(s)")
