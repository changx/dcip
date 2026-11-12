# dcip — datacenter, VPN, China-related and Meta IP lists

Rebuilt from public BGP, RIR and classification data. Every list is plain CIDR text, one prefix per line, with separate IPv4 and IPv6 files. The country files are `cidr,CC` CSV.

## Use the lists

### 1. Pick the lists

| Label | Files | Meaning | Action |
| --- | --- | --- | --- |
| `china` | `china-compliance-ipv4.txt`, `china-compliance-ipv6.txt` | Location in CN/HK/MO, or a Chinese entity network | Compliance flow |
| `china_dc` | `china-optimized-dc-ipv4.txt`, `china-optimized-dc-ipv6.txt` | China-line VPS/IDC (CN2, CMI, 9929 style) | Risk signal; combine with client signals |
| `meta` | `meta-ipv4.txt`, `meta-ipv6.txt` | Meta servers (crawler, webhooks) | Usually allow |
| `relay` | `relay-ipv4.txt`, `relay-ipv6.txt` | iCloud Private Relay egress (Apple list) | Real users; allow |
| `vpn` | `vpn-ipv4.txt`, `vpn-ipv6.txt` | Consumer VPN egress, inside and outside `combined` | Real users; allow, optional risk weight |
| `hosting` | `hosting-ipv4.txt`, `hosting-ipv6.txt` | `combined` minus `relay`, `vpn` and `meta`: servers, clouds, proxies, crawlers | Block |
| `datacenter` | `combined-ipv4.txt`, `combined-ipv6.txt` | Datacenter, hosting, commercial VPN space (superset kept for existing consumers) | Background risk signal |
| country | `country-ipv4.csv`, `country-ipv6.csv` | `cidr,CC` (ISO 3166-1 alpha-2), DB-IP Lite | Region rules |

`hosting`, `relay`, `vpn` and `meta` cover all of `combined`. `relay` and `vpn` also hold space outside `combined`
(VPN operators and X4BNet VPN ranges that no hosting signal catches).

Measured on one consumer site (paying users and registrations, Aug–Nov 2026): `combined` held 7.7% of the paying users,
`hosting` 0.7%. Registrations from `relay` and `vpn` paid at the same rate as unlisted (residential) addresses.

Download from one of these places:

- Latest commit: `https://raw.githubusercontent.com/changx/dcip/main/out/<file>`
- A fixed release: `gh release download <tag> -R changx/dcip -p '<file>'` (see the Releases page)

Pin a release tag in production if you need reproducible results.

### 2. Get the real client IP

Behind Cloudflare, read `CF-Connecting-IP`. Behind another reverse proxy, read a trusted `X-Forwarded-For`. Do not use the TCP peer address, because it is the proxy.

### 3. Label each IP (Python)

Load the lists once at startup. Each lookup is one binary search per list.

```python
import bisect, ipaddress, urllib.request

BASE = "https://raw.githubusercontent.com/changx/dcip/main/out/"
LISTS = {
    "china":      ["china-compliance-ipv4.txt", "china-compliance-ipv6.txt"],
    "china_dc":   ["china-optimized-dc-ipv4.txt", "china-optimized-dc-ipv6.txt"],
    "meta":       ["meta-ipv4.txt", "meta-ipv6.txt"],
    "datacenter": ["combined-ipv4.txt", "combined-ipv6.txt"],
}

class IPSet:
    def __init__(self, cidrs):
        nets = sorted((ipaddress.ip_network(c) for c in cidrs),
                      key=lambda n: (n.version, int(n.network_address)))
        self.r = {4: [], 6: []}
        for n in nets:
            self.r[n.version].append((int(n.network_address), int(n.broadcast_address)))
        self.s = {v: [a for a, _ in r] for v, r in self.r.items()}

    def __contains__(self, ip):
        a = ipaddress.ip_address(ip)
        i = bisect.bisect_right(self.s[a.version], int(a)) - 1
        return i >= 0 and self.r[a.version][i][1] >= int(a)

def fetch(name):
    return urllib.request.urlopen(BASE + name, timeout=60).read().decode().split()

SETS = {label: IPSet(c for f in files for c in fetch(f)) for label, files in LISTS.items()}

def labels(ip):
    return [label for label, s in SETS.items() if ip in s]

labels("157.240.1.1")     # ['meta', 'datacenter']
labels("155.254.126.10")  # ['china', 'china_dc', 'datacenter']
```

Reload the lists once a week. If a download fails, keep the lists already in memory.

### 4. Decide

1. `meta` matches: Meta infrastructure. Allow it unless the request is abnormal.
2. `china` matches: China-related for compliance. Send the request to your compliance flow.
3. `china_dc` matches without `china`: a China-line proxy or VPS. A browser time zone of `Asia/Shanghai` or `zh-CN` language makes a user in China likely.
4. `relay` or `vpn` matches: a privacy egress used by real users. Allow; add risk weight if needed.
5. `hosting` matches: server, cloud, proxy or crawler space. Block sign-ups and other protected writes.
6. No match: no IP evidence. Residential proxies are not visible to any static list.

Check the labels in this order: `meta`, `china`, `china_dc`, `relay`, `vpn`, `hosting`.

An IP match is evidence, not a legal determination. 28 CFR 202.211 defines covered persons by residence, ownership and control, so combine IP labels with KYC and contract data.

### In nginx

1. Make one map file per label. Example for `china`:
   `awk '{print $1" 1;"}' china-compliance-ipv4.txt china-compliance-ipv6.txt > /etc/nginx/ip-china.conf`
2. In the `http` block, add one `geo` block per label:
   `geo $ip_china { default 0; include /etc/nginx/ip-china.conf; }`
   Repeat with `$ip_china_dc`, `$ip_meta` and `$ip_dc`.
3. In the `location` block, pass the labels to the backend:
   `proxy_set_header X-IP-China $ip_china;` and the same for the other variables.
4. Run `nginx -t`, then `nginx -s reload`.

If nginx is behind a proxy, configure `real_ip_header` and `set_real_ip_from` first. Otherwise `geo` checks the proxy IP.

### Check one address from the command line

`./check.py 155.254.126.10 2a03:2880::1` prints every list in `out/` that covers the address.

### VPN

`vpn` (`build.py`) is the union of:

- prefixes originated by an ASN with the bgp.tools `vpn` tag, in X4BNet `input/vpn/ASN.txt`, or named as a VPN operator
  (PacketHub, Datacamp, Proton, Mullvad, IVPN, Windscribe, IPVanish, AnchorFree, Tefincom, Surfshark, Privado);
- X4BNet `output/vpn/ipv4.txt` ranges;
- Cloudflare WARP space (RIPE netname `CLOUDFLAREWARP`).

ASNs in `NOT_VPN` (Google, Amazon, Microsoft, Oracle, Cloudflare, Fastly, Akamai, DigitalOcean, Linode, Vultr, Hetzner,
OVH, Scaleway, Contabo, Alibaba, Tencent, M247, Zenlayer), eyeball ISPs and big carriers are never listed ASN-wide: their VPN
tag covers mostly servers and crawlers (Googlebot is AS15169). Addresses that `NOT_VPN` ASNs announce are removed from the X4BNet ranges too.
Their VPN products reach `vpn` only through WARP, or `relay` through Apple's list.

`relay` is Apple's published egress list (`data/apple-private-relay.csv`). `hosting` (`split.py`) is `combined` minus
`relay`, `vpn` and `meta`.

Not covered:

| Type | Extra source |
| --- | --- |
| Tor exits | https://check.torproject.org/torbulkexitlist (hourly) |
| Cloudflare WARP IPv4 (ARIN space) | Not in RIPE whois; lands in `hosting` |
| Residential proxies (real home IPs) | No static list works. Use a commercial service (Spur, IPinfo Privacy, ipapi.is) or behaviour signals. |

## Country

`country-ipv4.csv` / `country-ipv6.csv`: one `cidr,CC` line per CIDR from DB-IP Lite (monthly). Adjacent ranges of
one country are merged; unassigned space (`ZZ`) is left out. Look up the longest (only) matching CIDR.

Geolocation in `country-*` and `china-geo` (part of `china-compliance`): IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0.

## Rebuild

1. `BGPT_UA='myproject - me@example.com' ./fetch.sh`. This downloads all inputs into `data/`.
   bgp.tools asks for a contact address in the User-Agent.
   If bgp.tools shows a login page for the tag exports from your IP, set `BGPT_VIA=<ssh-host>` to fetch the tag CSVs through another host.
2. `systemd-run --user --scope -p MemoryMax=6G python3 build.py`. This writes `out/`.
   The first run parses RIPE/APNIC whois (about 5 minutes). Later runs use `data/whois_hosting.cache`.
3. `systemd-run --user --scope -p MemoryMax=6G python3 china.py`. This writes the `china-*` lists and adds China carrier overseas space to `combined`. Run it after `build.py`.
4. `python3 split.py`. This writes `hosting`. Run it after `china.py`.
5. `./selftest.py`. The last line must be `0 unexpected result(s)`.
6. `./guard.py`. It compares each `out/` list with the last commit by address space (IPv4 /24s, IPv6 /48s). It fails when a consumer list (`combined`, `meta`, `china-*`, `relay`, `vpn`, `hosting`, `country`) is missing, new, empty, or changed by more than 15% (`--max-change`). Use `--allow-new relay,vpn` for the first publication of a list. The intermediate tiers are reported only, because a few IPv6 /29 leases can move them by tens of percent. Review a failing change by hand before publishing it.

The lists are rebuilt and published daily. BGP announcements, RADB routes and IP leases change quickly.

## Sources

| Source | Use |
| --- | --- |
| bgp.tools `asns.csv`, tags `vpsh` `vpn` `cdn` `dsl` `mobile` | ASN class, hosting/VPN tags, eyeball tags |
| X4BNet/lists_vpn `input/*/ASN.txt`, `input/datacenter/ips` | Curated hosting ASNs and manual ranges |
| Stanford ASdb (2026-03) | "Hosting and Cloud Provider" category; non-commercial categories |
| PeeringDB `net` | `info_type` Content |
| CAIDA as-rel2 | AS relationships: China carrier adjacency, upstream inference |
| CAIDA RouteViews pfx2as (v4/v6) | Prefix to origin AS |
| RADB `AS-FACEBOOK` (whois.radb.net) | Meta's registered route/route6 objects for the Meta list |
| APNIC + RIPE inetnum/inet6num bulk | Sub-allocations named IDC/hosting/VPS/colo; `CLOUDFLAREWARP` netnames |
| X4BNet/lists_vpn `output/vpn/ipv4.txt` | Known VPN ranges for `vpn` |
| Apple `mask-api.icloud.com/egress-ip-ranges.csv` | iCloud Private Relay egress for `relay` |
| DB-IP Lite country | `country-*`, `china-geo` |

## Tiers

| File | Rule |
| --- | --- |
| `datacenter-core` | Strong tag (bgp.tools hosting/VPN/CDN or X4B) or two weak signals. Eyeball, T1 and big carriers are excluded. |
| `hosting-downstream` | No direct signal, ≤256 /24s, and every CAIDA upstream is a core ASN. |
| `china-adjacent` | Non-CN ASN with a weak signal, and a direct CAIDA neighbour of a China carrier ASN, or in the customer cone of a core ASN that is a direct neighbour. |
| `whois-hosting` | APNIC/RIPE inetnum ≤/16 whose netname/descr names hosting, IDC, VPS, colo or datacenter. |
| `combined` | Union of the four lists above. |
| `mixed-isp-hosting` | Strong hosting tag but the ASN is an eyeball ISP or big carrier. Not in `combined`. |
| `review` | China-adjacent, non-CN, no hosting signal. Not in `combined`. |

China carrier ASNs: 4134, 4809, 23764 (China Telecom); 4837, 9929, 10099, 19174 (China Unicom); 9808, 58453, 58807 (China Mobile).

## Organisation lists

| File | Rule |
| --- | --- |
| `meta-ipv4.txt` / `meta-ipv6.txt` | Every RADB route/route6 object of the `AS-FACEBOOK` AS-SET members: AS32934 (main), AS63293 (CDN), AS54115 (corporate), AS11917 (WhatsApp) and AS34825 (`radb.py`, saved as `data/radb-meta.json`). RADB holds registered routes. It covers every prefix that these ASNs announce in BGP, and also Meta space that is not announced at build time, such as `57.136.0.0/19`. `selftest.py` fails if RADB covers less than 90% of the BGP-announced Meta space. Meta's crawler (`facebookexternalhit`) and webhooks come from here. Meta caches inside ISP networks (FNA) use ISP addresses and are not included. |

## China labels (`china.py`)

"China" follows 28 CFR 202.208: the PRC including Hong Kong and Macau.

| File | Rule | Use |
| --- | --- | --- |
| `china-geo` | DB-IP Lite country is CN, HK or MO | Compliance |
| `china-registered` | RIR delegation country is CN, HK or MO (NRO stats) | Compliance |
| `china-entity-asn` | Origin ASN is registered in CN/HK/MO, has a Chinese group name (Alibaba, Tencent, Huawei, ByteDance, Baidu, China Telecom/Unicom/Mobile and others), or is a China carrier international ASN. Names are in `china-asn.csv`. | Compliance |
| `china-carrier-overseas` | All prefixes of CTG 23764, CMI 58453/58807, CUG 10099, CU Americas 19174; prefixes of CN2 4809 and CUII 9929 outside CN registration. Also added to `combined`. | Datacenter gap fill |
| `china-optimized-dc` | Datacenter ASNs that are China-line networks (see `china-line-asn.csv`): Rule A — connects to a China carrier, < 100 bilateral BGP peers, < 100 customers, ≤ 8192 /24s, not eyeball. Rule B — buys China carrier transit, connects to CT, CU and CM, < 300 customers. Plus customers of Rule A networks with ≤ 5 providers and ≤ 2048 /24s. | Risk |
| `china-compliance` | `geo` ∪ `registered` ∪ `entity-asn` | Compliance screen |
| `china-risk` | `compliance` ∪ `optimized-dc` | Risk signal |

Decision order for a visitor IP:

1. Hit in `china-compliance`: treat as China-related for compliance (location in CN/HK/MO, or a Chinese entity network).
2. Hit in `china-optimized-dc` only: a China-line VPS/proxy. Combine with client signals (time zone `Asia/Shanghai`, `zh-CN`) to estimate a user in China.
3. No hit: no IP evidence. Residential proxies stay invisible to any static list.

An IP hit is evidence, not a legal determination. 28 CFR 202.211 defines covered persons by residence, ownership and control, so use IP labels with KYC and contract data.

DB-IP Lite is CC BY 4.0. Show "IP Geolocation by DB-IP" (https://db-ip.com) where its data is used.

## Known limits

- China carrier overseas space has almost no rDNS, so IDC, enterprise DIA and transit inside it cannot be split. All of it is in `combined`.
- `china-optimized-dc` is a topology heuristic. On a hold-out check it flagged Contabo Asia and Gcore (direct China links, not China-line products) and missed JINX (HK, covered by `china-compliance`) and Nexeon. Use it as a weighted signal.
- DB-IP Lite and RIR registration are country-level and can lag real use by weeks.
- ARIN whois bulk data needs an agreement, so `whois-hosting` has no ARIN space.
- CAIDA misses many private CN2/CMI interconnects, so China adjacency is a lower bound.
- `hosting-downstream` includes some enterprises whose only upstream is a hosting provider.
