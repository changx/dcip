#!/usr/bin/env python3
"""China-related IP labels. Run after build.py (uses out/asn.csv).

"China" follows 28 CFR 202.208: PRC including Hong Kong and Macau.

Inputs (data/): nro-delegated-stats, dbip-country-lite.csv.gz, asns.csv,
                rv4/rv6.pfx2as.gz, out/asn.csv
Outputs (out/):
  china-geo-*            DB-IP Lite geolocates the range to CN/HK/MO
  china-registered-*     RIR delegation country is CN/HK/MO (NRO stats)
  china-entity-asn-*     origin ASN registered in CN/HK/MO, a Chinese group ASN,
                         or a China carrier international ASN
  china-carrier-overseas-*  CTG/CN2/CMI/CUG prefixes outside CN/HK/MO registration
  china-optimized-dc-*   datacenter prefixes whose ASN connects to China carriers
  china-compliance-*     geo ∪ registered ∪ entity-asn  (compliance screen)
  china-risk-*           compliance ∪ optimized-dc       (risk signal)
  china-asn.csv          ASNs in entity-asn with the reason
"""
import csv, gzip, ipaddress, re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
D, OUT = ROOT / "data", ROOT / "out"
CC = {"CN", "HK", "MO"}
CARRIER_INTL = {23764: "CTG", 4809: "CT CN2", 58453: "CMI", 58807: "CMIN2",
                10099: "CUG", 19174: "CU Americas", 9929: "CUII"}
GROUP = re.compile(
    r"alibaba|aliyun|alicloud|tencent|huawei|bytedance|byteplus|volcengine|baidu|"
    r"kingsoft|ksyun|\bucloud\b|jingdong|jd\.com|jdcloud|netease|qihoo|\bzte\b|"
    r"china ?telecom|chinanet|china ?unicom|china ?netcom|china ?mobile|"
    r"cmi\b|ctg\b|china ?cable|china ?broadnet|21vianet|vnet group|chinacache|"
    r"wangsu|cdnetworks|tencentcloud|sangfor|meituan|sankuai|\bxiaomi\b|pinduoduo|kuaishou", re.I)

def nets_from_range(lo, hi):
    return ipaddress.summarize_address_range(ipaddress.ip_address(lo), ipaddress.ip_address(hi))

lab = defaultdict(list)  # label -> [networks]

# 1. RIR registration country.
reg_asn = {}
with open(D / "nro-delegated-stats") as f:
    for line in f:
        p = line.split("|")
        if len(p) < 7 or p[1] not in CC or p[6] not in ("allocated", "assigned"):
            continue
        if p[2] == "ipv4":
            start = ipaddress.ip_address(p[3])
            lab["registered"] += nets_from_range(p[3], str(start + int(p[4]) - 1))
        elif p[2] == "ipv6":
            lab["registered"].append(ipaddress.ip_network(f"{p[3]}/{p[4]}"))
        elif p[2] == "asn":
            for a in range(int(p[3]), int(p[3]) + int(p[4])):
                reg_asn[a] = p[1]

# 2. Geolocation.
with gzip.open(D / "dbip-country-lite.csv.gz", "rt") as f:
    for lo, hi, cc in csv.reader(f):
        if cc in CC:
            lab["geo"] += nets_from_range(lo, hi)

# 3. Entity ASNs.
name, cc_bgpt, klass = {}, {}, {}
with open(D / "asns.csv", newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        s = r["asn"].upper().removeprefix("AS")
        if s.isdigit():
            name[int(s)], cc_bgpt[int(s)], klass[int(s)] = r["name"], r["cc"], r["class"]
entity = {}
for a, c in reg_asn.items():
    entity[a] = f"rir-registered:{c}"
for a, c in cc_bgpt.items():
    if c in CC:
        entity.setdefault(a, f"bgptools-cc:{c}")
for a, n in name.items():
    if GROUP.search(n):
        entity.setdefault(a, "chinese-group-name")
for a, n in CARRIER_INTL.items():
    entity[a] = f"china-carrier:{n}"

tiers = {int(r["asn"]): r for r in csv.DictReader(open(OUT / "asn.csv"))}

# ---------- China-line networks (CN2 GIA / CMI / 9929 style) ----------
# Rule A: connects (transit or peering) to a China carrier, has < 100 bilateral BGP peers
#         (IX route-server 'mlp' links not counted), < 100 customers, <= 8192 /24s, and is
#         not an eyeball network. Open-peering hosts (Hetzner, OVH, Vultr, AWS) and transit
#         carriers (Arelion, Tata, Telstra) fail.
# Rule B: buys transit from a China carrier, connects to all three carrier groups,
#         <= 8192 /24s, < 300 customers, < 300 bilateral BGP peers, and bgp.tools class is
#         not Content (Zenlayer). Content networks (Facebook, Gcore, i3D) buy China transit
#         to deliver their own traffic, not to resell China lines.
# Then add one level of customers under a Rule A network (Akari AS38136 under AS983),
# if the customer has <= 5 providers and <= 2048 /24s.
# Rule B networks sell wholesale transit, so their customers are not propagated.
GROUP_OF = {4134: "CT", 4809: "CT", 23764: "CT", 4837: "CU", 9929: "CU", 10099: "CU",
            19174: "CU", 9808: "CM", 58453: "CM", 58807: "CM"}
LINE_MAX_PEERS, LINE_MAX_CUST, LINE_MAX_24S = 100, 100, 8192
prov, peers, custs = defaultdict(set), defaultdict(set), defaultdict(set)
bgp_peers = defaultdict(int)
with open(D / "as-rel2.txt") as f:
    for line in f:
        if line.startswith("#"):
            continue
        a, b, rel, src = line.strip().split("|")[:4]
        a, b = int(a), int(b)
        if rel == "-1":
            prov[b].add(a); custs[a].add(b)
        else:
            peers[a].add(b); peers[b].add(a)
            if "bgp" in src:
                bgp_peers[a] += 1; bgp_peers[b] += 1
size = defaultdict(float)
with gzip.open(D / "rv4.pfx2as.gz", "rt") as f:
    for line in f:
        p, l, origins = line.split()
        for x in set(re.split(r"[_,]", origins)):
            if x.isdigit():
                size[int(x)] += 2 ** (24 - int(l)) if int(l) <= 24 else 1 / 256
eyeball = set()
for t in ("dsl", "mobile"):
    for line in (D / f"bgpt_{t}.csv").read_text().splitlines():
        s = line.split(",", 1)[0].upper().removeprefix("AS")
        if s.isdigit():
            eyeball.add(int(s))

china_line = {}
for a in set(prov) | set(peers):
    if a in GROUP_OF or a in eyeball:
        continue
    cn_prov = {GROUP_OF[x] for x in prov[a] if x in GROUP_OF}
    cn_any = cn_prov | {GROUP_OF[x] for x in peers[a] if x in GROUP_OF}
    if not cn_any or not 0 < size[a] <= LINE_MAX_24S:
        continue
    if bgp_peers[a] < LINE_MAX_PEERS and len(custs[a]) < LINE_MAX_CUST:
        china_line[a] = "small-direct:" + "+".join(sorted(cn_any))
    elif (cn_prov and cn_any == {"CT", "CU", "CM"} and len(custs[a]) < 300
          and bgp_peers[a] < 300 and klass.get(a) != "Content"):
        china_line[a] = "transit-all-groups"
for a in [x for x, why in china_line.items() if why.startswith("small-direct")]:
    for c in custs[a]:
        if (c not in GROUP_OF and c not in eyeball and len(prov[c]) <= 5
                and 0 < size[c] <= 2048):
            china_line.setdefault(c, f"customer-of:AS{a}")

dc_tiers = ("core", "downstream", "china-adjacent")
dc_china = {a for a in china_line if tiers.get(a, {}).get("tier") in dc_tiers}
with open(OUT / "china-line-asn.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["asn", "name", "why", "dc_tier", "v4_24s"])
    for a in sorted(china_line):
        w.writerow([a, tiers.get(a, {}).get("name", ""), china_line[a],
                    tiers.get(a, {}).get("tier", ""), round(size[a], 1)])

# Carrier overseas = not registered to mainland CN (HK-registered carrier space counts as overseas).
cn_only = []
with open(D / "nro-delegated-stats") as f:
    for line in f:
        p = line.split("|")
        if len(p) > 6 and p[1] == "CN" and p[6] in ("allocated", "assigned"):
            if p[2] == "ipv4":
                cn_only += nets_from_range(p[3], str(ipaddress.ip_address(p[3]) + int(p[4]) - 1))
            elif p[2] == "ipv6":
                cn_only.append(ipaddress.ip_network(f"{p[3]}/{p[4]}"))
reg_tree = {v: list(ipaddress.collapse_addresses(n for n in cn_only if n.version == v))
            for v in (4, 6)}
import bisect
reg_idx = {v: ([int(r.network_address) for r in reg_tree[v]], reg_tree[v]) for v in (4, 6)}
def registered_cn(n):
    starts, nets = reg_idx[n.version]
    i = bisect.bisect_right(starts, int(n.network_address)) - 1
    return i >= 0 and int(nets[i].broadcast_address) >= int(n.broadcast_address)

for fn in ("rv4.pfx2as.gz", "rv6.pfx2as.gz"):
    with gzip.open(D / fn, "rt") as f:
        for line in f:
            p, l, origins = line.split()
            asns = {int(x) for x in re.split(r"[_,]", origins) if x.isdigit()}
            n = ipaddress.ip_network(f"{p}/{l}", strict=False)
            if asns & set(entity):
                lab["entity-asn"].append(n)
            if asns & {23764, 58453, 58807, 10099, 19174}:
                lab["carrier-overseas"].append(n)  # international arms: no mainland residential
            elif asns & {4809, 9929} and not registered_cn(n):
                lab["carrier-overseas"].append(n)  # mainland backbones: overseas space only
            if asns & dc_china:
                lab["optimized-dc"].append(n)

def write(stem, nets):
    for v in (4, 6):
        agg = list(ipaddress.collapse_addresses(n for n in nets if n.version == v))
        (OUT / f"china-{stem}-ipv{v}.txt").write_text("".join(f"{n}\n" for n in agg))
    return sum(n.num_addresses for n in ipaddress.collapse_addresses(
        n for n in nets if n.version == 4)) / 256

lab["compliance"] = lab["geo"] + lab["registered"] + lab["entity-asn"]
lab["risk"] = lab["compliance"] + lab["optimized-dc"]
for k in ("geo", "registered", "entity-asn", "carrier-overseas", "optimized-dc", "compliance", "risk"):
    print(f"china-{k}: {write(k, lab[k]):,.0f} IPv4 /24-equivalents")

# Close the datacenter gap: carrier overseas space (IDC, DIA, transit; no PTR to split it)
# joins combined. CMHK residential/mobile is AS9231, which is not in CARRIER_INTL.
for v in (4, 6):
    p = OUT / f"combined-ipv{v}.txt"
    nets = [ipaddress.ip_network(x) for x in p.read_text().split()]
    nets += [n for n in lab["carrier-overseas"] if n.version == v]
    p.write_text("".join(f"{n}\n" for n in ipaddress.collapse_addresses(nets)))
print("combined-ipv4/6 updated with china-carrier-overseas")

with open(OUT / "china-asn.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["asn", "name", "reason", "dc_tier"])
    for a in sorted(entity):
        w.writerow([a, name.get(a, ""), entity[a], tiers.get(a, {}).get("tier", "")])
