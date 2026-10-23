# Phase 5 — Zone Walking

Reuses the Phase 3 signed, validating deployment. `example.com` is populated with hidden internal
service names (`dev, git, mail, vpn, backup, monitoring`) that are **not advertised anywhere**. With
**NSEC** authenticated denial the whole zone can be reconstructed from the apex name alone; switching
to **NSEC3** closes the leak.

## The signing option that permits the walk

`dnssec-signzone` defaults to **NSEC**, whose denial-of-existence record names the *next existing
name* in canonical order. Walking that chain enumerates the zone. The fix is **NSEC3**, which
publishes the chain over *hashes* of the names instead.

```bash
docker build -t cs6008-dnslab:base ../common
docker run --rm -v "$PWD":/phase5 -w /phase5 cs6008-dnslab:base sign/sign-all.sh nsec   # walkable
docker compose up -d
docker exec attacker make -C /attack
```

## Verify (5.2) — how the zone answers for a nonexistent name

```bash
docker exec client dig +dnssec nonexistent.example.com   # NXDOMAIN + an NSEC that names the neighbours
```

## Attack (5.3) — walk the zone (C/libpcap, no AXFR, no wordlist)

The walker crafts each query and reads each reply with libpcap. From `example.com` it follows the
NSEC chain, learning one new name per step:

```bash
docker exec attacker /attack/zonewalk eth0 172.16.2.10 example.com
# query 1  NSEC example.com            -> backup.example.com
# query 2  NSEC backup.example.com     -> dev.example.com
# ... recovers all 8 names in 9 queries (<= names + 2)
```

## The fix (5.3) — NSEC3 recovers nothing, denial still authenticates

```bash
docker exec attacker pkill -f zonewalk 2>/dev/null; true
docker run --rm -v "$PWD":/phase5 -w /phase5 cs6008-dnslab:base sign/sign-all.sh nsec3
docker compose restart domain-ns tld-ns root-ns resolver
docker exec client dig +dnssec nonexistent.example.com   # still NXDOMAIN, proven by a HASHED NSEC3
docker exec attacker /attack/zonewalk eth0 172.16.2.10 example.com   # recovers 0 names
```

## Files

- `config/domain-ns/db.example.com` — apex + www + 6 hidden internal names.
- `sign/sign-all.sh [nsec|nsec3]` — signs example.com with NSEC (walkable) or NSEC3 (fixed).
- `attack/zonewalk.c`, `attack/Makefile` — the libpcap NSEC walker.
- `evidence/` — the NSEC denial, the full walk (8 names / 9 queries), and the NSEC3 walk recovering 0.
