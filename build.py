#!/usr/bin/env python3
"""Build datacenter / VPN IP lists with a China-adjacent tier.

Inputs (in data/, fetched by fetch.sh):
  asns.csv                 bgp.tools ASN names, class, country
  bgpt_<tag>.csv           bgp.tools tag members (vpsh, vpn, cdn, dsl, mobile)
  asdb.csv                 Stanford ASdb categories
  pdb_net.json             PeeringDB networks (info_type)
  as-rel2.txt              CAIDA AS relationships (serial-2)
  rv4.pfx2as.gz, rv6.pfx2as.gz   CAIDA RouteViews prefix -> origin AS
  lists_vpn/               X4BNet/lists_vpn checkout

Outputs (in out/):
  datacenter-core-ipv4.txt / -ipv6.txt      high-confidence hosting/VPN ASNs
  hosting-downstream-ipv4.txt / -ipv6.txt   small ASNs whose upstreams are all hosting ASNs
  china-adjacent-ipv4.txt / -ipv6.txt       hosting-like ASNs near China carriers
  whois-hosting-ipv4.txt / -ipv6.txt        APNIC/RIPE sub-allocations named as hosting/IDC
  combined-ipv4.txt / -ipv6.txt             all four lists above (recommended)
  mixed-isp-hosting-ipv4.txt / -ipv6.txt    ISPs that also sell hosting (not in combined)
  review-ipv4.txt / -ipv6.txt               China-adjacent ASNs without hosting signal
  asn.csv                                   every selected ASN with tier and reasons
"""
import csv, gzip, ipaddress, json, re, sys
from collections import defaultdict, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent
D, OUT = ROOT / "data", ROOT / "out"
OUT.mkdir(exist_ok=True)

# International / backbone ASNs of China Telecom, China Unicom, China Mobile.
CHINA_CARRIERS = {
    4134: "CT ChinaNet", 4809: "CT CN2", 23764: "CT Global",
    4837: "CU Backbone", 9929: "CU CUII", 10099: "CU Global", 19174: "CU Americas",
    9808: "CM Backbone", 58453: "CM International", 58807: "CM International CMIN2",
}
CONE_LIMIT = 300  # expand customer cones only below this size (skip big transit)
KW = re.compile(r"host|cloud|\bidc\b|idc |server|vps|data ?cent|datacenter|colo|dedicat|"
                r"compute|virtual|proxy|vpn|cdn|ddos|\bdc\b|cyber ?space|netcup|"
                r"数据|云", re.I)

def asn_int(s):
    s = s.strip().upper().removeprefix("AS")
    return int(s) if s.isdigit() else None

# ---------- ASN metadata ----------
name, klass, cc = {}, {}, {}
with open(D / "asns.csv", newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        a = asn_int(r["asn"])
        if a is not None:
            name[a], klass[a], cc[a] = r["name"], r["class"], r["cc"]

def tag(t):
    p = D / f"bgpt_{t}.csv"
    s = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        a = asn_int(line.split(",", 1)[0])
        if a is not None:
            s.add(a)
    if not s:
        sys.exit(f"tag file {p} is empty or not CSV (bgp.tools login wall?)")
    return s

T = {t: tag(t) for t in ("vpsh", "vpn", "cdn", "dsl", "mobile")}

def x4b_asns(p):
    s = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        a = asn_int(line.split("#", 1)[0])
        if a is not None:
            s.add(a)
    return s

X4B = D / "lists_vpn"
x4b_dc = x4b_asns(X4B / "input/datacenter/ASN.txt")
x4b_vpn = x4b_asns(X4B / "input/vpn/ASN.txt")

asdb_host, asdb_noncommercial = set(), set()
NONCOMMERCIAL = {"Education and Research", "Government and Public Administration",
                 "Community Groups and Nonprofits", "Health Care Services",
                 "Finance and Insurance", "Manufacturing"}
with open(D / "asdb.csv", newline="", encoding="utf-8") as f:
    for r in csv.reader(f):
        a = asn_int(r[0]) if r else None
        if a is None:
            continue
        if "Hosting and Cloud Provider" in r[1:]:
            asdb_host.add(a)
        layer1 = {r[i] for i in range(1, len(r), 2) if r[i]}
        if layer1 and layer1 <= NONCOMMERCIAL:  # every category is non-hosting
            asdb_noncommercial.add(a)

pdb_content = set()
for n in json.load(open(D / "pdb_net.json"))["data"]:
    types = set(n.get("info_types") or []) | {n.get("info_type") or ""}
    if "Content" in types:
        pdb_content.add(n["asn"])
        name.setdefault(n["asn"], n["name"])

# ---------- originated address space (/24-equivalents, IPv4) ----------
size = defaultdict(float)
with gzip.open(D / "rv4.pfx2as.gz", "rt") as f:
    for line in f:
        p, l, origins = line.split()
        for x in set(re.split(r"[_,]", origins)):
            if x.isdigit():
                size[int(x)] += 2 ** (24 - int(l)) if int(l) <= 24 else 1 / 256

# ---------- AS graph ----------
customers, providers, neighbours = defaultdict(set), defaultdict(set), defaultdict(set)
with open(D / "as-rel2.txt") as f:
    for line in f:
        if line.startswith("#"):
            continue
        a, b, rel = line.split("|")[:3]
        a, b = int(a), int(b)
        neighbours[a].add(b); neighbours[b].add(a)
        if rel == "-1":
            customers[a].add(b); providers[b].add(a)

def cone(a, limit=None):
    seen, q = {a}, deque([a])
    while q:
        for c in customers[q.popleft()]:
            if c not in seen:
                seen.add(c); q.append(c)
                if limit and len(seen) > limit:
                    return None
    return seen

adj = {}  # asn -> how it reaches China carriers
for c, label in CHINA_CARRIERS.items():
    for n in customers[c]:  # buys transit from the China carrier: CN2 GIA / CMI / 9929 lines
        if n not in CHINA_CARRIERS:
            adj.setdefault(n, f"transit:{label}")
for c, label in CHINA_CARRIERS.items():
    for n in neighbours[c]:
        if n not in CHINA_CARRIERS:
            adj.setdefault(n, f"peer:{label}")
direct = set(adj)

# ---------- classify ----------
def reasons(a):
    r = []
    if a in T["vpsh"]: r.append("bgptools:hosting")
    if a in T["vpn"]: r.append("bgptools:vpn")
    if a in T["cdn"]: r.append("bgptools:cdn")
    if a in x4b_dc: r.append("x4b:dc")
    if a in x4b_vpn: r.append("x4b:vpn")
    if a in asdb_host: r.append("asdb:hosting")
    if a in pdb_content: r.append("peeringdb:content")
    if KW.search(name.get(a, "")): r.append("name-keyword")
    return r

STRONG = {"bgptools:hosting", "bgptools:vpn", "bgptools:cdn", "x4b:dc", "x4b:vpn"}
BIG_CARRIER_24S = 2048  # carriers above this size are not listed ASN-wide
DOWNSTREAM_MAX_24S = 256

def is_eyeball(a):
    """Hard eyeball: bgp.tools DSL/mobile tag. Class 'Eyeball' alone is soft:
    bgp.tools also gives it to China-facing IDCs such as Zenlayer and PEG TECH."""
    return a in T["dsl"] or a in T["mobile"]

def is_soft_eyeball(a):
    return klass.get(a) == "Eyeball"

def is_big_carrier(a):
    return klass.get(a) == "T1" or (klass.get(a) == "Carrier" and size[a] > BIG_CARRIER_24S) \
        or len(customers[a]) > CONE_LIMIT

tier = {}
candidates = (set(name) | set(adj) | x4b_dc | x4b_vpn | asdb_host | pdb_content) - set(CHINA_CARRIERS)
# Pass 1: direct evidence.
for a in candidates:
    r = reasons(a)
    strong, medium = bool(STRONG & set(r)), len(set(r) - STRONG)
    broad = is_eyeball(a) or is_big_carrier(a) or (is_soft_eyeball(a) and medium == 0)
    if (strong or medium >= 2) and not broad:
        tier[a] = ("core", r)
    elif strong:
        tier[a] = ("mixed", r)
core = {a for a, (t, _) in tier.items() if t == "core"}

# China adjacency also covers customer cones of hosting networks that connect
# directly to China carriers (for example AS983 -> AS38136).
for n in direct & core:
    for m in (cone(n, CONE_LIMIT) or ()):
        if m != n and m not in CHINA_CARRIERS:
            adj.setdefault(m, f"via-hosting:AS{n}")
for a in core:
    if a in adj:
        tier[a][1].append("china:" + adj[a])

# Pass 2: inference for ASNs without direct evidence.
for a in candidates - set(tier):
    if is_eyeball(a) or is_soft_eyeball(a) or a in asdb_noncommercial:
        continue
    r = reasons(a)
    ups, downs = providers[a], customers[a]
    if len(downs) >= 2 and len(downs & core) * 2 >= len(downs) and not is_big_carrier(a):
        r.append("customers-mostly-hosting")
    if ups and ups <= core and 0 < size[a] <= DOWNSTREAM_MAX_24S:
        # Every upstream is a hosting network: a VPS / proxy / IP-transit reseller.
        tier[a] = ("downstream", r + ["all-upstreams-hosting"])
    elif "customers-mostly-hosting" in r and a not in adj:
        tier[a] = ("downstream", r)
    elif a in adj and cc.get(a) != "CN" and r:
        tier[a] = ("china-adjacent", r)
    elif a in adj and cc.get(a) != "CN" and size[a] > 0:
        tier[a] = ("review", r)

ORDER = ["core", "downstream", "china-adjacent", "mixed", "review"]

# ---------- prefixes ----------
pfx = {t: [] for t in ORDER}
for fn in ("rv4.pfx2as.gz", "rv6.pfx2as.gz"):
    with gzip.open(D / fn, "rt") as f:
        for line in f:
            p, l, origins = line.split()
            asns = {int(x) for x in re.split(r"[_,]", origins) if x.isdigit()}
            ts = [tier[a][0] for a in asns if a in tier]
            if not ts:
                continue
            best = min(ts, key=ORDER.index)
            pfx[best].append(ipaddress.ip_network(f"{p}/{l}", strict=False))

# Add X4BNet's manual IP entries (its ASN list is already a signal above).
for p in sorted((X4B / "input/datacenter/ips").glob("*.txt")):
    for line in p.read_text().splitlines():
        try:
            pfx["core"].append(ipaddress.ip_network(line.split("#")[0].strip(), strict=False))
        except ValueError:
            pass

# ---------- RIR whois sub-allocations (APNIC + RIPE) ----------
WHOIS_KW = re.compile(
    r"\bIDC\b|IDC[-_ ]|[-_]IDC|hosting|\bvps\b|[-_]vps|vps[-_]|datacent|data[- ]cent|"
    r"colocation|\bcolo\b|dedicated[- ]serv|server[- ]?(farm|room)|机房|数据中心|"
    r"cloud[- ]?(server|hosting|comput)", re.I)
WHOIS_DBS = ["apnic.db.inetnum.gz", "apnic.db.inet6num.gz",
             "ripe.db.inetnum.gz", "ripe.db.inet6num.gz"]
cache = D / "whois_hosting.cache"
srcs = [D / x for x in WHOIS_DBS if (D / x).exists()]
if srcs and (not cache.exists() or cache.stat().st_mtime < max(s.stat().st_mtime for s in srcs)):
    sys.path.insert(0, str(ROOT))
    from whois_parse import ranges
    with open(cache, "w") as out:
        for s in srcs:
            for lo, hi, nn, de, wcc, st in ranges(s):
                big = (int(hi) - int(lo) + 1) > (65536 if lo.version == 4 else 2 ** 96)
                if not big and WHOIS_KW.search(f"{nn} {de}"):
                    for n in ipaddress.summarize_address_range(lo, hi):
                        out.write(f"{n}\t{nn}\n")
pfx["whois"] = [ipaddress.ip_network(l.split("\t")[0]) for l in open(cache)] if cache.exists() else []

def write(stem, nets):
    for v in (4, 6):
        agg = ipaddress.collapse_addresses(n for n in nets if n.version == v)
        (OUT / f"{stem}-ipv{v}.txt").write_text("".join(f"{n}\n" for n in agg))

for old in OUT.glob("*-ipv[46].txt"):
    old.unlink()
write("datacenter-core", pfx["core"])
write("hosting-downstream", pfx["downstream"])
write("china-adjacent", pfx["china-adjacent"])
write("whois-hosting", pfx["whois"])
write("combined", pfx["core"] + pfx["downstream"] + pfx["china-adjacent"] + pfx["whois"])
write("mixed-isp-hosting", pfx["mixed"])
write("review", pfx["review"])

with open(OUT / "asn.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["asn", "tier", "name", "cc", "class", "v4_24s", "china_path", "reasons"])
    for a in sorted(tier):
        t, r = tier[a]
        w.writerow([a, t, name.get(a, ""), cc.get(a, ""), klass.get(a, ""), round(size[a], 1),
                    adj.get(a, ""), ";".join(r)])

counts = defaultdict(int)
for t, _ in tier.values():
    counts[t] += 1
print("ASNs per tier:", dict(counts))
for stem in ("datacenter-core", "hosting-downstream", "china-adjacent", "whois-hosting",
             "combined", "mixed-isp-hosting", "review"):
    n4 = (OUT / f"{stem}-ipv4.txt").read_text().split()
    addrs = sum(ipaddress.ip_network(x).num_addresses for x in n4)
    print(f"{stem}: {len(n4)} IPv4 CIDRs, {addrs/256:,.0f} /24-equivalents")
