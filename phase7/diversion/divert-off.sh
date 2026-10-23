#!/bin/sh
ip route del 172.16.1.10/32 2>/dev/null || true
ip route del 172.16.1.11/32 2>/dev/null || true
echo "[edge-router] downstream diversion OFF"
