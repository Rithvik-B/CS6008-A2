#!/bin/sh
# Generic per-node entrypoint for the DNS lab.
#   STATIC_ROUTES="CIDR:GW CIDR:GW ..."  -> installed with `ip route replace` (needs NET_ADMIN)
#   ENABLE_FORWARDING=1                  -> turn this node into a router (IP forwarding, no NAT)
# After wiring the network it exec's the container CMD (named, http server, interceptor, ...).
set -e

if [ "$ENABLE_FORWARDING" = "1" ]; then
    # Routers forward between their two subnets. No NAT / masquerade is added here:
    # isolation + "only routers forward" is the whole point.
    # ip_forward is set via compose `sysctls:` at container creation (namespaced,
    # and /proc/sys is read-only here). Just report what we actually got.
    echo "[entrypoint] router mode: ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)"
fi

if [ -n "$STATIC_ROUTES" ]; then
    for spec in $STATIC_ROUTES; do
        dest="${spec%%:*}"
        gw="${spec##*:}"
        if ip route replace "$dest" via "$gw"; then
            echo "[entrypoint] route $dest via $gw"
        else
            echo "[entrypoint] WARN: failed to add route $dest via $gw" >&2
        fi
    done
fi

# Optional extra routes added as raw `ip` commands (used for attack diversion on routers).
if [ -n "$EXTRA_IP_CMDS" ]; then
    echo "$EXTRA_IP_CMDS" | while IFS= read -r cmd; do
        [ -z "$cmd" ] && continue
        echo "[entrypoint] + $cmd"
        eval "$cmd" || echo "[entrypoint] WARN: '$cmd' failed" >&2
    done
fi

echo "[entrypoint] exec: $*"
exec "$@"
