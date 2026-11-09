#!/usr/bin/env python3
"""Refuse to publish a rebuild whose lists changed too much.

Compares every out/*-ipv4.txt / *-ipv6.txt in the working tree with the same file
at a Git ref (default HEAD). Size is measured as address space, not line count,
because collapsing can merge many lines into one:
IPv4 in /24 equivalents, IPv6 in /48 equivalents.

Fails (exit 1) when a list is missing, new, empty, or its size changed by more
than --max-change (default 0.15). Prints one line per list.

Usage: python3 guard.py [--base REF] [--max-change 0.15]
"""
import argparse, ipaddress, subprocess, sys
from pathlib import Path

R = Path(__file__).resolve().parent


def size(text, v):
    nets = ipaddress.collapse_addresses(ipaddress.ip_network(x) for x in text.split())
    unit = 8 if v == 4 else 80
    return sum(n.num_addresses for n in nets) / (1 << unit)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="HEAD")
    ap.add_argument("--max-change", type=float, default=0.15)
    a = ap.parse_args()
    old_names = set(subprocess.check_output(
        ["git", "-C", str(R), "ls-tree", "--name-only", a.base, "out/"], text=True).split())
    old_names = {Path(n).name for n in old_names if n.endswith((".txt",)) and "-ipv" in n}
    new_names = {p.name for p in (R / "out").glob("*-ipv[46].txt")}
    bad = 0
    for name in sorted(old_names | new_names):
        if name not in new_names or name not in old_names:
            print(f"BAD {name}: {'missing' if name not in new_names else 'new'} list")
            bad += 1
            continue
        v = 4 if name.endswith("ipv4.txt") else 6
        new = (R / "out" / name).read_text()
        old = subprocess.check_output(["git", "-C", str(R), "show", f"{a.base}:out/{name}"], text=True)
        s_new, s_old = size(new, v), size(old, v)
        if s_new == 0:
            print(f"BAD {name}: empty")
            bad += 1
            continue
        change = (s_new - s_old) / s_old if s_old else 1.0
        ok = abs(change) <= a.max_change
        bad += not ok
        print(f"{'ok ' if ok else 'BAD'} {name}: {s_old:,.0f} -> {s_new:,.0f} ({change:+.1%})")
    print(f"guard: {bad} list(s) outside ±{a.max_change:.0%}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
