#!/bin/sh
# PERMISSIVE client: try DoT; if it does not return a valid answer for ANY reason
# (blocked transport, bad cert, tampered session), fall back to cleartext DNS.
out=$(dig +tls +tls-ca=/ca/ca.crt +tls-hostname=resolver.cs6008.local \
      @resolver.cs6008.local +short +timeout=3 +tries=1 example.com 2>/dev/null)
if echo "$out" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "via DoT: $out"
else
    echo "DoT unavailable -> CLEARTEXT fallback:"
    dig +short +timeout=3 +tries=1 @172.16.2.10 example.com
fi
