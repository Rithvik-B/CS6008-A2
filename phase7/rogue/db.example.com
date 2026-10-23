$TTL 60
@   IN SOA ns.example.com. admin.example.com. ( 1 3600 600 604800 60 )
@   IN NS  ns.example.com.
ns  IN A   172.16.2.10
@   IN A   172.16.1.30
www IN A   172.16.1.30
