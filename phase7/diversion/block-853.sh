#!/bin/sh
# Run ON edge-router. Attack (iii): deny the encrypted transport by dropping DoT (853).
iptables -C FORWARD -p tcp --dport 853 -j DROP 2>/dev/null || iptables -I FORWARD -p tcp --dport 853 -j DROP
iptables -C FORWARD -p tcp --sport 853 -j DROP 2>/dev/null || iptables -I FORWARD -p tcp --sport 853 -j DROP
echo "[edge-router] DoT (tcp/853) BLOCKED"
