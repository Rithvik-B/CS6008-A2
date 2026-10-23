; example.com. zone — authoritative on domain-ns (172.16.3.30)
; Public names: apex + www. Hidden internal service names: dev, git, mail, vpn,
; backup, monitoring — not advertised anywhere, discoverable only by enumeration.
$TTL 3600
@               IN  SOA ns.example.com. admin.example.com. (
                        2026102301 3600 600 604800 3600 )
@               IN  NS  ns.example.com.
ns.example.com. IN  A   172.16.3.30
; --- public ---
@               IN  A   172.16.1.20
www             IN  A   172.16.1.20
; --- hidden internal services (not published anywhere) ---
dev             IN  A   172.16.1.21
git             IN  A   172.16.1.22
mail            IN  A   172.16.1.23
vpn             IN  A   172.16.1.24
backup          IN  A   172.16.1.25
monitoring      IN  A   172.16.1.26
