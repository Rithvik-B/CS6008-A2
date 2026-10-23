#!/bin/sh
iptables -D FORWARD -p tcp --dport 853 -j DROP 2>/dev/null || true
iptables -D FORWARD -p tcp --sport 853 -j DROP 2>/dev/null || true
echo "[edge-router] DoT (tcp/853) unblocked"
