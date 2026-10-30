#!/usr/bin/env bash
# Download all inputs into data/. bgp.tools tag CSVs need a non-blocked egress;
# set BGPT_VIA=<ssh-host> to fetch them through another SSH host.
# bgp.tools asks for a contact in the User-Agent: set BGPT_UA.
set -euo pipefail
cd "$(dirname "$0")"; mkdir -p data; cd data
UA="${BGPT_UA:-dcip-ip-list - set BGPT_UA to 'project - you@example.com'}"
C=https://publicdata.caida.org/datasets

curl -sfL -A "$UA" -o asns.csv https://bgp.tools/asns.csv
TAGS="vpsh vpn cdn dsl mobile"
if [ -n "${BGPT_VIA:-}" ]; then
  ssh "$BGPT_VIA" "cd /tmp && for t in $TAGS; do curl -sfL -A '$UA' -o bgpt_\$t.csv https://bgp.tools/tags/\$t.csv; done"
  for t in $TAGS; do scp -q "$BGPT_VIA:/tmp/bgpt_$t.csv" .; done
else
  for t in $TAGS; do curl -sfL -A "$UA" -o "bgpt_$t.csv" "https://bgp.tools/tags/$t.csv"; done
fi

curl -sfL -o asdb.csv https://asdb.stanford.edu/static-website/data/2026-03_categorized_ases.csv
curl -sfL -o pdb_net.json 'https://www.peeringdb.com/api/net?fields=asn,name,info_type,info_types,website'

rel=$(curl -sf $C/as-relationships/serial-2/ | grep -o '[0-9]\{8\}.as-rel2.txt.bz2' | sort -u | tail -1)
curl -sf $C/as-relationships/serial-2/$rel | bunzip2 > as-rel2.txt

ym=$(date -u +%Y/%m)
for v in 2:rv2:routeviews-prefix2as 6:rv6:routeviews6-prefix2as; do
  IFS=: read n tag dir <<<"$v"
  f=$(curl -sf $C/routing/$dir/$ym/ | grep -o "routeviews-$tag-[0-9-]*.pfx2as.gz" | sort -u | tail -1)
  curl -sf -o "rv${n/2/4}.pfx2as.gz" $C/routing/$dir/$ym/$f
done

if [ -d lists_vpn/.git ]; then git -C lists_vpn pull -q --ff-only
else git clone -q --depth 1 https://github.com/X4BNet/lists_vpn.git; fi

# RIR whois bulk data (no personal data). ARIN/LACNIC/AFRINIC bulk needs an agreement.
for u in https://ftp.apnic.net/apnic/whois/apnic.db.inetnum.gz \
         https://ftp.apnic.net/apnic/whois/apnic.db.inet6num.gz \
         https://ftp.ripe.net/ripe/dbase/split/ripe.db.inetnum.gz \
         https://ftp.ripe.net/ripe/dbase/split/ripe.db.inet6num.gz; do
  curl -sfL -m 1200 -R -z "$(basename $u)" -O "$u"
done
echo "fetch ok"
