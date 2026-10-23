/*
 * zonewalk.c  --  NSEC zone-walker (C + libpcap)
 *
 * Reconstructs the full contents of a signed zone from knowledge of the apex
 * name ALONE, using only DNS queries -- no AXFR, no wordlist. It exploits NSEC
 * authenticated denial of existence: the NSEC record at each name names the
 * NEXT existing name in canonical order (so it can prove non-existence of
 * everything in between, signed ahead of time). Following that chain from the
 * apex walks every name in the zone.
 *
 * All packets are crafted and sent with libpcap (pcap_inject) and all replies
 * are read with libpcap (pcap capture) -- no resolver library is used. Queries
 * go to the recursive resolver, which fetches and returns the signed NSECs.
 *
 * Build: make
 * Run:   ./zonewalk <iface> <resolver-ip> <zone>
 *   e.g. ./zonewalk eth0 172.16.2.10 example.com
 */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define ETH_HLEN 14
#define T_NSEC 47

static uint8_t our_mac[6], res_mac[6];
static uint32_t our_ip, res_ip_n;
static pcap_t *pc;

static int if_mac(const char *ifn, uint8_t m[6]){
    int s=socket(AF_INET,SOCK_DGRAM,0); if(s<0)return -1;
    struct ifreq r; memset(&r,0,sizeof r); strncpy(r.ifr_name,ifn,IFNAMSIZ-1);
    if(ioctl(s,SIOCGIFHWADDR,&r)<0){close(s);return -1;} memcpy(m,r.ifr_hwaddr.sa_data,6); close(s); return 0;
}
static int if_ip(const char *ifn, uint32_t *ip){
    int s=socket(AF_INET,SOCK_DGRAM,0); if(s<0)return -1;
    struct ifreq r; memset(&r,0,sizeof r); strncpy(r.ifr_name,ifn,IFNAMSIZ-1);
    if(ioctl(s,SIOCGIFADDR,&r)<0){close(s);return -1;}
    *ip=((struct sockaddr_in*)&r.ifr_addr)->sin_addr.s_addr; close(s); return 0;
}
static int neigh_mac(const char *ip, uint8_t m[6]){
    char cmd[128]; snprintf(cmd,sizeof cmd,"ping -c1 -W1 %s >/dev/null 2>&1",ip);
    for(int a=0;a<5;a++){ system(cmd); FILE*f=fopen("/proc/net/arp","r"); if(!f)return -1;
        char line[256]; fgets(line,sizeof line,f);
        while(fgets(line,sizeof line,f)){ char aip[64],hw[64],x[64],dev[64],t[64],fl[64];
            if(sscanf(line,"%63s %63s %63s %63s %63s %63s",aip,t,fl,hw,x,dev)>=4 &&
               strcmp(aip,ip)==0 && strcmp(hw,"00:00:00:00:00:00")!=0){ unsigned v[6];
                if(sscanf(hw,"%x:%x:%x:%x:%x:%x",v,v+1,v+2,v+3,v+4,v+5)==6){
                    for(int i=0;i<6;i++){m[i]=v[i];}
                    fclose(f); return 0; } } }
        fclose(f); usleep(200000);} return -1;
}
/* decompress a DNS name; return wire bytes consumed at off */
static int dns_name(const uint8_t*m,int ml,int off,char*out,int cap){
    int we=-1,o=0,hops=0; out[0]=0;
    while(off<ml){ uint8_t l=m[off];
        if((l&0xC0)==0xC0){ if(off+1>=ml)return -1; if(we<0)we=off+2; off=((l&0x3F)<<8)|m[off+1]; if(++hops>128)return -1; continue;}
        if(l==0){ if(we<0)we=off+1; break;} off++; if(off+l>ml)return -1;
        for(int i=0;i<l&&o<cap-2;i++){out[o++]=m[off+i];}
        out[o++]='.'; off+=l; }
    if(o>0&&out[o-1]=='.')o--;
    out[o]=0;
    return we;
}
static int write_name(const char*d,uint8_t*out){
    if(!d[0]||(d[0]=='.'&&!d[1])){out[0]=0;return 1;} int o=0; const char*p=d;
    while(*p){ const char*dot=strchr(p,'.'); int l=dot?(int)(dot-p):(int)strlen(p); if(l>63)l=63;
        out[o++]=l; memcpy(out+o,p,l); o+=l; if(!dot)break; p=dot+1; } out[o++]=0; return o;
}
static uint16_t ipck(const uint8_t*ip,int ihl){ uint32_t s=0;
    for(int i=0;i<ihl;i+=2)s+=(ip[i]<<8)|ip[i+1];
    while(s>>16)s=(s&0xFFFF)+(s>>16);
    return ~s; }
static uint16_t udpck(const uint8_t*ip,const uint8_t*u,int ul){ uint32_t s=0;
    for(int i=12;i<20;i+=2)s+=(ip[i]<<8)|ip[i+1];
    s+=17; s+=ul;
    for(int i=0;i+1<ul;i+=2)s+=(u[i]<<8)|u[i+1];
    if(ul&1)s+=u[ul-1]<<8;
    while(s>>16)s=(s&0xFFFF)+(s>>16);
    uint16_t c=~s; return c?c:0xFFFF; }

/* build a query for the immediate canonical successor of `name`:
   qname = "\000"+name (a nonexistent subname), qtype A, with EDNS DO=1 so the
   resolver returns the signed NSEC that proves it does not exist. */
static int build_query(const char*name,uint16_t id,uint8_t*fr){
    uint8_t *ip=fr+ETH_HLEN, *udp=ip+20, *dns=udp+8;
    dns[0]=id>>8; dns[1]=id&0xFF; dns[2]=0x01; dns[3]=0x00;   /* RD=1 */
    dns[4]=0;dns[5]=1; dns[6]=0;dns[7]=0; dns[8]=0;dns[9]=0; dns[10]=0;dns[11]=1; /* qd=1 ar=1(OPT) */
    int o=12;
    dns[o++]=0x01; dns[o++]=0x00;              /* leading "\000" label -> successor */
    o+=write_name(name,dns+o);                 /* + name + root */
    dns[o++]=0;dns[o++]=1;                      /* qtype  A  */
    dns[o++]=0;dns[o++]=1;                      /* qclass IN */
    /* EDNS0 OPT with DO=1 */
    dns[o++]=0x00;                              /* root name   */
    dns[o++]=0x00; dns[o++]=0x29;              /* type 41 OPT */
    dns[o++]=0x10; dns[o++]=0x00;              /* UDP size 4096 */
    dns[o++]=0x00; dns[o++]=0x00; dns[o++]=0x80; dns[o++]=0x00; /* ext-rcode/ver/flags: DO=1 */
    dns[o++]=0x00; dns[o++]=0x00;              /* rdlen 0 */
    int dnslen=o, udplen=8+dnslen, iptot=20+udplen;
    udp[0]=0x30;udp[1]=0x39; udp[2]=0;udp[3]=53; udp[4]=udplen>>8;udp[5]=udplen&0xFF; udp[6]=0;udp[7]=0;
    ip[0]=0x45;ip[1]=0; ip[2]=iptot>>8;ip[3]=iptot&0xFF; ip[4]=0;ip[5]=0;
    ip[6]=0x40;ip[7]=0; ip[8]=64; ip[9]=17; ip[10]=0;ip[11]=0;
    memcpy(ip+12,&our_ip,4); memcpy(ip+16,&res_ip_n,4);
    uint16_t c=ipck(ip,20); ip[10]=c>>8;ip[11]=c&0xFF;
    c=udpck(ip,udp,udplen); udp[6]=c>>8;udp[7]=c&0xFF;
    memcpy(fr,res_mac,6); memcpy(fr+6,our_mac,6); fr[12]=0x08;fr[13]=0x00;
    return ETH_HLEN+iptot;
}

/* in a reply, return the next-name of the NSEC whose owner == `want`.
   (An NXDOMAIN proof may carry several NSECs; we want the one owned by `want`,
   whose next-name is `want`'s successor in the zone.) return 1 if found. */
static int find_nsec_next(const uint8_t*dns,int dnslen,const char*want,char*out,int cap){
    if(dnslen<12)return 0;
    int qd=(dns[4]<<8)|dns[5];
    int tot=qd+((dns[6]<<8)|dns[7])+((dns[8]<<8)|dns[9])+((dns[10]<<8)|dns[11]);
    int off=12; char nm[256];
    for(int i=0;i<qd;i++){int c=dns_name(dns,dnslen,off,nm,sizeof nm); if(c<0)return 0; off=c+4;}
    for(int i=qd;i<tot;i++){
        int c=dns_name(dns,dnslen,off,nm,sizeof nm); if(c<0)return 0; off=c;
        if(off+10>dnslen)return 0;
        int type=(dns[off]<<8)|dns[off+1]; int rdl=(dns[off+8]<<8)|dns[off+9]; int rdata=off+10;
        if(type==T_NSEC && strcasecmp(nm,want)==0){
            int cc=dns_name(dns,dnslen,rdata,out,cap); if(cc<0)return 0; return 1; }
        off=rdata+rdl;
    }
    return 0;
}

/* send one NSEC query for `name`, wait for the reply, return next-name (or NULL) */
static int query_next(const char*name,char*nextout,int cap){
    uint8_t fr[1600]; uint16_t id=(uint16_t)(rand()&0xFFFF);
    int fl=build_query(name,id,fr);
    for(int attempt=0;attempt<4;attempt++){
        if(pcap_inject(pc,fr,fl)<0){fprintf(stderr,"inject: %s\n",pcap_geterr(pc));return 0;}
        time_t deadline=time(NULL)+2;
        while(time(NULL)<deadline){
            struct pcap_pkthdr*h; const u_char*p; int r=pcap_next_ex(pc,&h,&p);
            if(r<=0) continue;
            if(h->caplen<ETH_HLEN+28) continue;
            const uint8_t*ip=p+ETH_HLEN; int ihl=(ip[0]&0x0F)*4;
            const uint8_t*udp=ip+ihl; const uint8_t*dns=udp+8;
            int udplen=(udp[4]<<8)|udp[5]; int dnslen=udplen-8;
            if(dnslen<12||dns+dnslen>p+h->caplen) continue;
            if(((dns[0]<<8)|dns[1])!=id) continue;           /* match our txid */
            if(find_nsec_next(dns,dnslen,name,nextout,cap)) return 1;
            return 0;   /* reply with no NSEC (shouldn't happen mid-walk) */
        }
        /* timeout -> retransmit */
    }
    return 0;
}

int main(int argc,char**argv){
    if(argc!=4){fprintf(stderr,"usage: %s <iface> <resolver-ip> <zone>\n",argv[0]);return 1;}
    const char*iface=argv[1],*rip=argv[2],*zone=argv[3];
    srand(time(NULL)^getpid());
    if(if_mac(iface,our_mac)<0){fprintf(stderr,"no iface mac\n");return 1;}
    if(if_ip(iface,&our_ip)<0){fprintf(stderr,"no iface ip\n");return 1;}
    res_ip_n=inet_addr(rip);
    if(neigh_mac(rip,res_mac)<0){fprintf(stderr,"no resolver mac\n");return 1;}
    char eb[PCAP_ERRBUF_SIZE];
    pc=pcap_open_live(iface,65535,0,100,eb); if(!pc){fprintf(stderr,"pcap: %s\n",eb);return 1;}
    char filt[160]; snprintf(filt,sizeof filt,"udp and src port 53 and src host %s",rip);
    struct bpf_program bp;
    if(pcap_compile(pc,&bp,filt,1,PCAP_NETMASK_UNKNOWN)<0||pcap_setfilter(pc,&bp)<0){
        fprintf(stderr,"filter: %s\n",pcap_geterr(pc));return 1;}

    printf("NSEC zone-walk of '%s' via resolver %s (libpcap craft+capture, no AXFR/wordlist)\n\n",zone,rip);
    char current[256]; snprintf(current,sizeof current,"%s",zone);
    char found[256][256]; int nfound=0, nq=0;
    for(;;){
        char nextn[256];
        if(!query_next(current,nextn,sizeof nextn)){ printf("  (no NSEC for %s -- stopping)\n",current); break; }
        nq++;
        printf("  query %-2d  NSEC %-24s ->  %s\n",nq,current,nextn);
        if(strcasecmp(nextn,zone)==0){ printf("  (next wrapped to apex -- walk complete)\n"); break; }
        snprintf(found[nfound++],256,"%s",nextn);
        snprintf(current,sizeof current,"%s",nextn);
        if(nfound>=250) break;
    }
    printf("\nRecovered %d name(s) in %d queries:\n",nfound,nq);
    printf("  %s\t(apex)\n",zone);
    for(int i=0;i<nfound;i++) printf("  %s\n",found[i]);
    pcap_close(pc);
    return 0;
}
