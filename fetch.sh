#!/usr/bin/env bash
# Download all inputs into data/. bgp.tools tag CSVs need a non-blocked egress;
# set BGPT_VIA=<ssh-host> to fetch them through another SSH host.
# bgp.tools asks for a contact in the User-Agent: set BGPT_UA.
set -euo pipefail
cd "$(dirname "$0")"; mkdir -p data; cd data
UA="${BGPT_UA:-dcip-ip-list - set BGPT_UA to 'project - you@example.com'}"
C=https://publicdata.caida.org/datasets

curl -sSfL --retry 3 --retry-delay 30 --retry-all-errors -A "$UA" -o asns.csv https://bgp.tools/asns.csv
TAGS="vpsh vpn cdn dsl mobile ddosm"
if [ -n "${BGPT_VIA:-}" ]; then
  ssh "$BGPT_VIA" "cd /tmp && for t in $TAGS; do curl -sSfL --retry 3 --retry-delay 30 --retry-all-errors -A '$UA' -o bgpt_\$t.csv https://bgp.tools/tags/\$t.csv; done"
  for t in $TAGS; do scp -q "$BGPT_VIA:/tmp/bgpt_$t.csv" .; done
else
  for t in $TAGS; do curl -sSfL --retry 3 --retry-delay 30 --retry-all-errors -A "$UA" -o "bgpt_$t.csv" "https://bgp.tools/tags/$t.csv"; done
fi

curl -sSfL --retry 3 --retry-delay 30 --retry-all-errors -o asdb.csv https://asdb.stanford.edu/static-website/data/2026-03_categorized_ases.csv
# PeeringDB throttles anonymous bulk queries (HTTP 429). Its data changes slowly, so a
# failed download keeps the previous file when it is less than 7 days old.
if curl -sSfL --retry 3 --retry-delay 30 --retry-all-errors --retry-max-time 180 --max-time 120 -o pdb_net.json.tmp 'https://www.peeringdb.com/api/net?fields=asn,name,info_type,info_types,website'; then
  mv pdb_net.json.tmp pdb_net.json
elif [ -s pdb_net.json ] && [ $(( $(date +%s) - $(stat -c %Y pdb_net.json) )) -lt 604800 ]; then
  rm -f pdb_net.json.tmp
  echo "warning: PeeringDB download failed; keeping pdb_net.json from $(date -u -r pdb_net.json +%FT%TZ)" >&2
else
  echo "PeeringDB download failed and no pdb_net.json newer than 7 days" >&2; exit 1
fi

rel=$(curl -sSf --retry 3 --retry-delay 30 --retry-all-errors $C/as-relationships/serial-2/ | grep -o '[0-9]\{8\}.as-rel2.txt.bz2' | sort -u | tail -1)
curl -sSf --retry 3 --retry-delay 30 --retry-all-errors $C/as-relationships/serial-2/$rel | bunzip2 > as-rel2.txt

ym=$(date -u +%Y/%m)
for v in 2:rv2:routeviews-prefix2as 6:rv6:routeviews6-prefix2as; do
  IFS=: read n tag dir <<<"$v"
  f=$(curl -sSf --retry 3 --retry-delay 30 --retry-all-errors $C/routing/$dir/$ym/ | grep -o "routeviews-$tag-[0-9-]*.pfx2as.gz" | sort -u | tail -1)
  curl -sSf --retry 3 --retry-delay 30 --retry-all-errors -o "rv${n/2/4}.pfx2as.gz" $C/routing/$dir/$ym/$f
done

if [ -d lists_vpn/.git ]; then git -C lists_vpn pull -q --ff-only
else git clone -q --depth 1 https://github.com/X4BNet/lists_vpn.git; fi

# RIR whois bulk data (no personal data). ARIN/LACNIC/AFRINIC bulk needs an agreement.
for u in https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz \
         https://ftp.apnic.net/apnic/whois/apnic.db.inet6num.gz \
         https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz \
         https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz; do
  curl -sSfL --retry 3 --retry-delay 30 --retry-all-errors -m 1200 -R -z "$(basename $u)" -O "$u"
done

# China labels: NRO combined delegation stats (all RIRs) and DB-IP Lite country geolocation.
# DB-IP Lite is CC BY 4.0: show "IP Geolocation by DB-IP" (https://db-ip.com) where it is used.
curl -sSfL --retry 3 --retry-delay 30 --retry-all-errors -m 600 -o nro-delegated-stats https://ftp.ripe.net/pub/stats/ripencc/nro-stats/latest/nro-delegated-stats
curl -sSfL --retry 3 --retry-delay 30 --retry-all-errors -m 600 -o dbip-country-lite.csv.gz \
  "https://download.db-ip.com/free/dbip-country-lite-$(date -u +%Y-%m).csv.gz" \
  || curl -sSfL --retry 3 --retry-delay 30 --retry-all-errors -m 600 -o dbip-country-lite.csv.gz \
  "https://download.db-ip.com/free/dbip-country-lite-$(date -u -d '-1 month' +%Y-%m).csv.gz"
# Meta's registered routes (RADB AS-FACEBOOK), merged into out/meta-* by build.py.
python3 ../radb.py radb-meta.json
echo "fetch ok"
