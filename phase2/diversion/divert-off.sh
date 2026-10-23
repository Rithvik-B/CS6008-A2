#!/bin/sh
# Remove the diversion; replies go straight to the resolver again (connected route).
ip route del 172.16.2.10/32 2>/dev/null || true
echo "[core-router] diversion OFF"
ip route get 172.16.2.10
