#!/bin/sh
# Run ON core-router. Divert every reply bound for the resolver (172.16.2.10)
# to the attacker (172.16.2.100) first. This is a route on the ROUTER only --
# the resolver and nameservers keep their Phase 1 configuration untouched.
ip route replace 172.16.2.10/32 via 172.16.2.100
echo "[core-router] diversion ON: 172.16.2.10 via 172.16.2.100"
ip route get 172.16.2.10
