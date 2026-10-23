; example.com. zone — authoritative on domain-ns (172.16.3.30, answers as ns.example.com)
$TTL 3600
@               IN  SOA ns.example.com. admin.example.com. (
                        2026102301 ; serial
                        3600 600 604800 3600 )
@               IN  NS  ns.example.com.
ns.example.com. IN  A   172.16.3.30
; --- the legitimate site: example.com and www point at webserver (172.16.1.20) ---
@               IN  A   172.16.1.20
www             IN  A   172.16.1.20
