# dcip — datacenter / VPN IP list with a China-adjacent tier

## Run

1. `BGPT_UA='myproject - me@example.com' ./fetch.sh`. This downloads all inputs into `data/`.
   bgp.tools asks for a contact address in the User-Agent.
   If bgp.tools shows a login page for the tag exports from your IP, set `BGPT_VIA=<ssh-host>` to fetch the tag CSVs through another host.
2. `systemd-run --user --scope -p MemoryMax=6G python3 build.py`. This writes `out/`.
   The first run parses RIPE/APNIC whois (about 5 minutes). Later runs use `data/whois_hosting.cache`.
3. `./check.py 155.254.126.0/24 1.2.3.4`. This shows which lists cover an address.

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

## Known limits

- Overseas IDC ranges that the China carriers announce from their own ASNs are not split out in whois. They are not in `combined`.
- ARIN whois bulk data needs an agreement, so `whois-hosting` has no ARIN space.
- CAIDA misses many private CN2/CMI interconnects, so China adjacency is a lower bound.
- `hosting-downstream` includes some enterprises whose only upstream is a hosting provider.
