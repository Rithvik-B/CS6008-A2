# CS6008 Assignment 2 — DNS Security

A self-contained DNS security lab built in Docker: a three-tier DNS hierarchy is stood up,
attacked from an on-path position, and then defended one layer at a time (DNSSEC, downgrade
resistance, NSEC3, last-mile forgery, DoT). Everything runs on isolated Docker bridges; nothing
touches the real Internet. All attack tooling is C/C++ with `libpcap`.

**Author:** Bathula Rithvik (23B0939)
**Report:** [`report.pdf`](report.pdf) — one section per phase (design, evidence, answers).

## Layout

```
common/         shared base image (BIND 9.20 on debian:trixie) + node entrypoint
phase1/ .. 7/   each phase, self-contained: compose.yml, configs, scripts, attack source, README, evidence
report/         report.tex (LaTeX source for report.pdf)
report.pdf      the submitted report
```

Each `phaseN/README.md` lists the exact commands to **deploy, attack, and verify** that phase from
a clean checkout.

## Topology (fixed addresses, three bridges)

| subnet | nodes |
|--------|-------|
| client `172.16.1.0/24` | client `.10`, webserver `.20`, rogue-web `.30`, attacker `.100` (P6–7), edge-router `.2` |
| resolver `172.16.2.0/24` | resolver `.10`, attacker `.100` (P2–5), edge-router `.2`, core-router `.3` |
| authoritative `172.16.3.0/24` | root-ns `.10`, tld-ns `.20`, domain-ns `.30`, core-router `.3` |

The routers are the only forwarders (IP forwarding, **no NAT**); IP masquerade is disabled on each
bridge, so the only path between subnets is a router container with a foot in both. Every other node
pins `net.ipv4.ip_forward=0` and reaches off-subnet addresses through static routes.

## Prerequisites

Docker Engine/Desktop with Compose and Buildx, able to run containers with `NET_ADMIN` (routers) and
`NET_RAW` (attacker). ~4 cores / ~8 GB RAM / ~15 GB disk. Developed and tested on Linux.

## Quick start (per phase)

```bash
# 1. build the shared base image once
docker build -t cs6008-dnslab:base ./common

# 2. enter a phase and follow its README
cd phase1 && docker compose up -d        # phase 1 needs no signing/PKI
# phases 3–7 first run:  sign/sign-all.sh   (and phase 7 also: pki/make-ca.sh)
```

## The seven phases

1. **Building the DNS Hierarchy** — three-tier BIND, isolation, referral capture.
2. **On-Path Response Forgery** — libpcap interceptor poisons the resolver's cache.
3. **DNSSEC Chain of Trust** — signed zones + validating resolver; the forgery now SERVFAILs.
4. **Signature Stripping & Downgrade** — Run A resists; Run B (parent publishes no DS) succeeds.
5. **Zone Walking** — a libpcap NSEC walker recovers all hidden names; NSEC3 closes the leak.
6. **Last-Mile Response Forgery** — a plain stub is poisoned; a validating stub catches it.
7. **Encrypting the Last Mile (DoT)** — private CA + by-name cert; three attacks × two clients.

## Notes on reproducibility

Only sources, configs, and scripts are committed. Regenerated artifacts — compiled binaries, signed
zones, DNSSEC keys, PKI keys/certs, and LaTeX build files — are `.gitignore`d; the per-phase scripts
rebuild them. No private key is committed.
