; com. zone — authoritative on tld-ns (172.16.3.20, answers as ns.com)
$TTL 3600
@               IN  SOA ns.com. admin.ns.com. (
                        2026102301 ; serial
                        3600 600 604800 3600 )
; --- com's own nameserver ---
@               IN  NS  ns.com.
ns.com.         IN  A   172.16.3.20
; --- delegation of example.com. to the domain nameserver (in-bailiwick glue) ---
example.com.    IN  NS  ns.example.com.
ns.example.com. IN  A   172.16.3.30
