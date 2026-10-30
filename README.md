# dcip — datacenter / VPN IP list with a China-adjacent tier

## Run

1. `BGPT_UA='myproject - me@example.com' ./fetch.sh`. This downloads all inputs into `data/`.
   bgp.tools asks for a contact address in the User-Agent.
   If bgp.tools shows a login page for the tag exports from your IP, set `BGPT_VIA=<ssh-host>` to fetch the tag CSVs through another host.
2. `systemd-run --user --scope -p MemoryMax=6G python3 build.py`. This writes `out/`.
   The first run parses RIPE/APNIC whois (about 5 minutes). Later runs use `data/whois_hosting.cache`.
3. `systemd-run --user --scope -p MemoryMax=6G python3 china.py`. This writes the `china-*` lists and adds China carrier overseas space to `combined`. Run it after `build.py`.
4. `./selftest.py`. Every line must show `ok`.
5. `./check.py 155.254.126.0/24 1.2.3.4`. This shows which lists cover an address.

## Query visitor IPs

Use `out/combined-ipv4.txt` and `out/combined-ipv6.txt`. A hit means the IP is datacenter space.
Use the real client IP. Behind Cloudflare or a reverse proxy, read `CF-Connecting-IP` or a trusted `X-Forwarded-For`, not `remote_addr`.

### In application code (Python)

Load the files once at startup. Each lookup is one binary search.

```python
import bisect, ipaddress

class IPSet:
    def __init__(self, *files):
        nets = [ipaddress.ip_network(l) for f in files for l in open(f).read().split()]
        self.v = {4: [], 6: []}
        for n in sorted(nets, key=lambda n: (n.version, int(n.network_address))):
            self.v[n.version].append((int(n.network_address), int(n.broadcast_address)))
        self.starts = {k: [s for s, _ in r] for k, r in self.v.items()}

    def __contains__(self, ip):
        a = ipaddress.ip_address(ip)
        i = bisect.bisect_right(self.starts[a.version], int(a)) - 1
        return i >= 0 and self.v[a.version][i][1] >= int(a)

dc = IPSet("out/combined-ipv4.txt", "out/combined-ipv6.txt")
"155.254.126.10" in dc   # True
```

### In nginx

1. Convert the list: `awk '{print $1" 1;"}' out/combined-ipv4.txt out/combined-ipv6.txt > /etc/nginx/dc.conf`
2. In the `http` block, add `geo $is_dc { default 0; include /etc/nginx/dc.conf; }`.
3. In the `location` block, add `proxy_set_header X-Is-DC $is_dc;`.
4. Run `nginx -t`, then `nginx -s reload`.

If nginx is behind a proxy, configure `real_ip_header` and `set_real_ip_from` first. Otherwise `geo` checks the proxy IP.

### VPN

`combined` catches most commercial VPNs and self-hosted VPN/proxy servers, because they run on datacenter IPs. It does not catch these:

| Type | Extra source |
| --- | --- |
| Tor exits | https://check.torproject.org/torbulkexitlist (hourly) |
| iCloud Private Relay | https://mask-api.icloud.com/egress-ip-ranges.csv |
| Known VPN ranges | X4BNet `output/vpn/ipv4.txt` |
| Residential proxies (real home IPs) | No static list works. Use a commercial service (Spur, IPinfo Privacy, ipapi.is) or behaviour signals. |

### Advice

- Use a hit as a risk signal, not as an automatic block. Corporate egress, cloud crawlers and API clients also use datacenter IPs.
- Rebuild weekly. BGP announcements and IP leases change quickly.

## Sources

| Source | Use |
| --- | --- |
| bgp.tools `asns.csv`, tags `vpsh` `vpn` `cdn` `dsl` `mobile` | ASN class, hosting/VPN tags, eyeball tags |
| X4BNet/lists_vpn `input/*/ASN.txt`, `input/datacenter/ips` | Curated hosting ASNs and manual ranges |
| Stanford ASdb (2026-03) | "Hosting and Cloud Provider" category; non-commercial categories |
| PeeringDB `net` | `info_type` Content |
| CAIDA as-rel2 | AS relationships: China carrier adjacency, upstream inference |
| CAIDA RouteViews pfx2as (v4/v6) | Prefix to origin AS |
| APNIC + RIPE inetnum/inet6num bulk | Sub-allocations named IDC/hosting/VPS/colo |

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
| `meta-ipv4.txt` / `meta-ipv6.txt` | Every BGP prefix of AS32934 (main), AS63293 (CDN) and AS54115 (corporate). Meta's crawler (`facebookexternalhit`) and webhooks come from here. Meta caches inside ISP networks (FNA) use ISP addresses and are not included. |

## Label visitor IPs

Load each list once and return every label that matches. Base URL: `https://raw.githubusercontent.com/changx/dcip/main/out/`.

| Label | Files | Action |
| --- | --- | --- |
| `china` | `china-compliance-ipv4/6.txt` | Compliance flow (CN/HK/MO location or Chinese entity network) |
| `china_dc` | `china-optimized-dc-ipv4/6.txt` | Risk signal; combine with `Asia/Shanghai` time zone and `zh-CN` |
| `meta` | `meta-ipv4/6.txt` | Meta servers; usually allow |
| `datacenter` | `combined-ipv4/6.txt` | Background risk signal |

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
