"""Stream RPSL inetnum/inet6num objects -> (first_ip, last_ip, netname, descr, country, status)."""
import gzip, ipaddress
def objects(path):
    obj = {}
    key = None
    with gzip.open(path, "rt", encoding="latin-1") as f:
        for line in f:
            if line.startswith(("%", "#")):
                continue
            if not line.strip():
                if obj: yield obj
                obj, key = {}, None
                continue
            if line[0] in " \t+" and key:
                obj[key] += " " + line.strip(); continue
            k, _, v = line.partition(":")
            key = k.strip().lower()
            v = v.strip()
            obj[key] = obj[key] + " | " + v if key in obj and key == "descr" else obj.get(key, v) if key in obj else v
    if obj: yield obj

def ranges(path):
    for o in objects(path):
        if "inetnum" in o:
            a, _, b = o["inetnum"].partition("-")
            try: lo, hi = ipaddress.ip_address(a.strip()), ipaddress.ip_address(b.strip())
            except ValueError: continue
        elif "inet6num" in o:
            try: n = ipaddress.ip_network(o["inet6num"], strict=False)
            except ValueError: continue
            lo, hi = n.network_address, n.broadcast_address
        else:
            continue
        yield lo, hi, o.get("netname", ""), o.get("descr", ""), o.get("country", ""), o.get("status", "")
