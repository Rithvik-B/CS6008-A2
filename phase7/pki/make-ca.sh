#!/bin/sh
# make-ca.sh -- stand up a private CA and issue the resolver's DoT certificate.
# The resolver cert's ONLY SAN is DNS:resolver.cs6008.local (no IP SAN), so the
# client must reach the resolver BY NAME and validate the cert against that name.
# Also mints a SEPARATE rogue CA + rogue cert (same name) for the impersonation attack.
set -e
cd "$(dirname "$0")/.."
RNAME=resolver.cs6008.local
rm -rf pki/out && mkdir -p pki/out/trusted pki/out/rogue

gen_ca () {  # <dir> <cn>
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$1/ca.key" -out "$1/ca.crt" -days 3650 -subj "/CN=$2" >/dev/null 2>&1
}
issue () {   # <cadir> <outdir> -- issue resolver cert for $RNAME signed by that CA
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$2/resolver.key" -out "$2/resolver.csr" -subj "/CN=$RNAME" >/dev/null 2>&1
    cat > "$2/ext.cnf" <<X
subjectAltName = DNS:$RNAME
X
    openssl x509 -req -in "$2/resolver.csr" -CA "$1/ca.crt" -CAkey "$1/ca.key" \
        -CAcreateserial -days 3650 -extfile "$2/ext.cnf" -out "$2/resolver.crt" >/dev/null 2>&1
}

echo "[pki] trusted CA + resolver cert (SAN DNS:$RNAME, no IP SAN)"
gen_ca pki/out/trusted "CS6008 Lab Root CA"
issue pki/out/trusted pki/out/trusted

echo "[pki] ROGUE CA + rogue resolver cert (same name, untrusted issuer) for impersonation"
gen_ca pki/out/rogue "EVIL Root CA"
issue pki/out/rogue pki/out/rogue

# place the resolver's real key/cert where BIND will read them
mkdir -p config/resolver/tls
cp pki/out/trusted/resolver.crt config/resolver/tls/resolver.crt
cp pki/out/trusted/resolver.key config/resolver/tls/resolver.key
# the CA the clients trust
cp pki/out/trusted/ca.crt config/resolver/tls/ca.crt
echo "[pki] done. verify SAN:"
openssl x509 -in pki/out/trusted/resolver.crt -noout -ext subjectAltName | sed 's/^/    /'
