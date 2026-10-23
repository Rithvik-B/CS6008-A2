# Shared base image for every node in the CS6008 A2 DNS lab.
# Debian trixie ships BIND 9.20.x (required by the assignment).
# One image for all roles; behaviour is chosen by the compose command + configs.
FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# tshark asks (debconf) whether non-root may capture: preseed "no" so the
# install is non-interactive. We run captures as root anyway.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      bind9 bind9-utils bind9-dnsutils \
      iproute2 iputils-ping \
      tcpdump tshark \
      gcc g++ make libpcap-dev \
      curl openssl procps \
      python3 \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Generic entrypoint: install per-node static routes (NET_ADMIN) from the
# STATIC_ROUTES env var, enable forwarding only where asked, then exec CMD.
COPY scripts/node-entrypoint.sh /usr/local/bin/node-entrypoint.sh
RUN chmod +x /usr/local/bin/node-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/node-entrypoint.sh"]
CMD ["sleep", "infinity"]
