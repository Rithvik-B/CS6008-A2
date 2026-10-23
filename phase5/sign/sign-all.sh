#!/bin/sh
# sign-all.sh [nsec|nsec3] -- sign the hierarchy; example.com uses the chosen
# authenticated-denial scheme:
#   nsec  (default): NSEC chain  -> the zone is WALKABLE (Phase 5 attack works)
#   nsec3          : hashed NSEC3 -> the simple online walk recovers NOTHING (the fix)
# root and com are always NSEC (only example.com is under test).
# Run from phase5/:  docker run --rm -v "$PWD":/phase5 -w /phase5 cs6008-dnslab:base sign/sign-all.sh [nsec|nsec3]
set -e
ALG=ECDSAP256SHA256
MODE="${1:-nsec}"
NSEC3SALT=DEADBEEF            # fixed salt so runs are reproducible
cd "$(dirname "$0")/.."
ROOT=config/root-ns; TLD=config/tld-ns; DOM=config/domain-ns; RES=config/resolver

echo "[sign] mode=$MODE : cleaning previous keys/signed zones"
rm -rf keys build; mkdir -p keys/root keys/com keys/example.com build
rm -f "$ROOT/db.root.signed" "$TLD/db.com.signed" "$DOM/db.example.com.signed" "$RES/trust-anchor.conf"

keygen() { dnssec-keygen -a "$ALG" -n ZONE -K "$1" "$2" >/dev/null
           dnssec-keygen -a "$ALG" -n ZONE -f KSK -K "$1" "$2" >/dev/null; }

# ---- 1. example.com: NSEC (default) or NSEC3 (-3 salt) ----
keygen keys/example.com example.com
cp "$DOM/db.example.com" build/db.example.com
if [ "$MODE" = "nsec3" ]; then
    echo "[sign] signing example.com with NSEC3 (salt $NSEC3SALT) -- walk-resistant"
    dnssec-signzone -S -K keys/example.com -3 "$NSEC3SALT" -H 0 \
        -o example.com -f "$DOM/db.example.com.signed" -d keys build/db.example.com >/dev/null
else
    echo "[sign] signing example.com with NSEC -- WALKABLE"
    dnssec-signzone -S -K keys/example.com \
        -o example.com -f "$DOM/db.example.com.signed" -d keys build/db.example.com >/dev/null
fi

# ---- 2. com (NSEC), publishes example.com DS ----
keygen keys/com com
cat "$TLD/db.com" keys/dsset-example.com. > build/db.com
dnssec-signzone -S -K keys/com -o com -f "$TLD/db.com.signed" -d keys build/db.com >/dev/null

# ---- 3. root (NSEC), publishes com DS ----
keygen keys/root .
cat "$ROOT/db.root" keys/dsset-com. > build/db.root
dnssec-signzone -S -K keys/root -o . -f "$ROOT/db.root.signed" -d keys build/db.root >/dev/null

# ---- 4. resolver trust anchor = root KSK ----
ksk=$(grep -l "IN DNSKEY 257" keys/root/K*.key | head -1)
key=$(grep "IN DNSKEY 257" "$ksk" | sed 's/.*DNSKEY //')
set -- $key; flags=$1; proto=$2; alg=$3; shift 3; b64="$*"
{ echo "// Root KSK trust anchor (generated)."; echo "trust-anchors {";
  echo "    . static-key $flags $proto $alg \"$b64\";"; echo "};"; } > "$RES/trust-anchor.conf"

echo "[sign] DONE (example.com denial = $([ "$MODE" = nsec3 ] && echo NSEC3 || echo NSEC))"
