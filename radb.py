#!/usr/bin/env python3
"""Fetch Meta's registered routes from RADB into data/radb-meta.json.

Expands the AS-FACEBOOK AS-SET recursively, then collects every route/route6
object whose origin is one of its ASNs. RADB route objects are registrations:
they can include prefixes that are not announced in BGP right now (for example
WhatsApp AS11917). build.py merges them into the Meta list.

Usage: python3 radb.py [output]   (default data/radb-meta.json)
"""
import ipaddress, json, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path

HOST = "whois.radb.net"
ROOT_SET = "AS-FACEBOOK"


def whois(*args):
    p = subprocess.run(["whois", "-h", HOST, *args], capture_output=True, text=True, timeout=120)
    if p.returncode != 0:
        sys.exit(f"whois {' '.join(args)} failed: {p.stderr.strip()}")
    return p.stdout


def expand(name, seen):
    name = name.upper()
    if name in seen:
        return set()
    seen.add(name)
    asns = set()
    for line in whois(name).splitlines():
        if not line.lower().startswith("members:"):
            continue
        for m in line.split(":", 1)[1].replace(",", " ").split():
            m = m.upper()
            if m.startswith("AS-"):
                asns |= expand(m, seen)
            elif m.startswith("AS") and m[2:].isdigit():
                asns.add(int(m[2:]))
    return asns


def main():
    out = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent / "data/radb-meta.json")
    asns = sorted(expand(ROOT_SET, set()))
    if not asns:
        sys.exit(f"{ROOT_SET}: no member ASNs")
    nets = set()
    for a in asns:
        for line in whois("--", f"-i origin AS{a}").splitlines():
            key = line.split(":", 1)[0].lower()
            if key in ("route", "route6"):
                n = ipaddress.ip_network(line.split(":", 1)[1].strip(), strict=False)
                if n.prefixlen == 0 or n.is_private:
                    sys.exit(f"AS{a}: refusing route {n}")
                nets.add(n)
    v4 = sorted((n for n in nets if n.version == 4), key=lambda n: (int(n.network_address), n.prefixlen))
    v6 = sorted((n for n in nets if n.version == 6), key=lambda n: (int(n.network_address), n.prefixlen))
    if not v4 or not v6:
        sys.exit("RADB returned an empty address family")
    data = {
        "source": f"RADB {ROOT_SET} recursive AS-SET route/route6 origin lookup",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "asns": asns,
        "ipv4": [str(n) for n in v4],
        "ipv6": [str(n) for n in v6],
    }
    tmp = out.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1) + "\n")
    tmp.replace(out)
    print(f"radb ok: ASNs {asns}, {len(v4)} IPv4, {len(v6)} IPv6 routes")


if __name__ == "__main__":
    main()
