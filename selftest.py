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
    ("combined-ipv4.txt", "Cloudflare (incl. WARP), Vultr, Akamai Prolexic", "high", [13335, 20473, 32787]),
    ("combined-ipv4.txt", "Cox (cable ISP, bgp.tools class Content)", "low", [22773]),
    ("combined-ipv4.txt", "DDoS-protected enterprises (Ahold, Vonage, UniCredit, American Airlines)",
     "low", [26539, 22343, 197636, 29982]),
    ("meta-ipv4.txt", "Meta ASNs", "high", [32934, 63293, 54115]),
    ("meta-ipv4.txt", "non-Meta networks", "low", [16509, 15169, 8075, 7922, 4134]),
    ("vpn-ipv4.txt", "VPN operators (Datacamp, PacketHub, Proton, Mullvad, IPVanish)", "high",
     [212238, 136787, 207137, 208172, 197141, 46253]),
    ("vpn-ipv4.txt", "clouds, CDNs, generic hosts, residential/mobile", "low",
     [15169, 396982, 16509, 8075, 13335, 54113, 24940, 16276, 9009, 14061, 21859,
      7922, 7018, 21928, 2856, 5089]),
    ("hosting-ipv4.txt", "clouds and generic hosts", "high", [16509, 14061, 24940, 16276, 20473, 63949]),
    ("hosting-ipv4.txt", "VPN operators, Meta, residential/mobile", "low",
     [212238, 136787, 32934, 63293, 7922, 7018, 21928, 2856]),
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

# Every registered Meta RADB route must be covered by the Meta lists.
import json
radb = json.load(open(R / "data/radb-meta.json"))
for v in (4, 6):
    meta = list(ipaddress.collapse_addresses(
        ipaddress.ip_network(x) for x in (R / "out" / f"meta-ipv{v}.txt").read_text().split()))
    missing = [x for x in radb[f"ipv{v}"]
               if not any(ipaddress.ip_network(x).subnet_of(m) for m in meta)]
    fails += bool(missing)
    print(f"== meta-ipv{v}.txt: RADB AS-FACEBOOK routes covered: "
          f"{len(radb[f'ipv{v}']) - len(missing)}/{len(radb[f'ipv{v}'])}" + (f" BAD {missing[:5]}" if missing else " ok"))
# Class lists: meta, relay, vpn and hosting cover all of combined; hosting has none of the others.
def ranges(stem, v):
    nets = ipaddress.collapse_addresses(
        ipaddress.ip_network(x) for x in (R / "out" / f"{stem}-ipv{v}.txt").read_text().split())
    return [(int(n.network_address), int(n.broadcast_address)) for n in nets]

def overlap(a, b):
    i = j = 0; n = 0
    while i < len(a) and j < len(b):
        lo, hi = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if lo <= hi: n += hi - lo + 1
        if a[i][1] < b[j][1]: i += 1
        else: j += 1
    return n

def merged(*lists):
    out = []
    for lo, hi in sorted(x for l in lists for x in l):
        if out and lo <= out[-1][1] + 1: out[-1] = (out[-1][0], max(out[-1][1], hi))
        else: out.append((lo, hi))
    return out

for v in (4, 6):
    comb, host = ranges("combined", v), ranges("hosting", v)
    others = merged(ranges("relay", v), ranges("vpn", v), ranges("meta", v))
    size = sum(hi - lo + 1 for lo, hi in comb)
    covered = overlap(comb, merged(host, others))
    mixed = overlap(host, others)
    ok = covered == size and mixed == 0
    fails += not ok
    print(f"== classes ipv{v}: combined covered {covered}/{size}, hosting overlap {mixed}: {'ok' if ok else 'BAD'}")

# Spot addresses: class (first of meta, relay, vpn, hosting) and country.
def has(stem, ip):
    a = ipaddress.ip_address(ip)
    return any(lo <= int(a) <= hi for lo, hi in ranges(stem, a.version))

for ip, want in [("172.224.226.5", "relay"), ("2a09:bac5::1", "vpn"), ("66.249.66.1", "hosting"),
                 ("157.240.1.1", "meta"), ("81.2.69.142", None)]:
    got = next((s for s in ("meta", "relay", "vpn", "hosting") if has(s, ip)), None)
    fails += got != want
    print(f"  {'ok ' if got == want else 'BAD'} {ip}: {got} (expect {want})")

country = {}
for v in (4, 6):
    for line in (R / "out" / f"country-ipv{v}.csv").read_text().splitlines():
        c, cc = line.split(",")
        country[ipaddress.ip_network(c)] = cc
for ip, want in [("8.8.8.8", "US"), ("81.2.69.142", "GB"), ("1.0.1.1", "CN"), ("193.0.6.139", "NL")]:
    a = ipaddress.ip_address(ip)
    got = next((cc for n, cc in country.items() if n.version == a.version and a in n), None)
    fails += got != want
    print(f"  {'ok ' if got == want else 'BAD'} country {ip}: {got} (expect {want})")
print(f"{fails} unexpected result(s)")
