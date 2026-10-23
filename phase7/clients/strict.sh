#!/bin/sh
# STRICT client: DoT only, validate the resolver cert against our private CA and
# the hostname. NO cleartext fallback -- if encrypted+authenticated DNS is not
# available, it fails closed.
dig +tls +tls-ca=/ca/ca.crt +tls-hostname=resolver.cs6008.local \
    @resolver.cs6008.local +short +timeout=3 +tries=1 example.com 2>&1
