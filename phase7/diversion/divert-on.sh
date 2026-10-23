#!/bin/sh
# Run ON edge-router. Divert the resolver's client-bound replies through the
# attacker (172.16.1.100) on the client subnet. A route on the ROUTER only --
# the clients' own configuration is untouched, and there is no ARP spoofing.
ip route replace 172.16.1.10/32 via 172.16.1.100   # Client A
ip route replace 172.16.1.11/32 via 172.16.1.100   # Client B
echo "[edge-router] downstream diversion ON: 172.16.1.10,172.16.1.11 via 172.16.1.100"
