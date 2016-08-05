#include "handlers.hpp"

#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

namespace bpf_test
{

using Ethernet = ether_header;
using Ipv4 = ip;
using Tcp = tcphdr;
using Udp = udphdr;

namespace
{


inline void
log_tcp_header(Ipv4* ip4, u_char const* pkt, FILE* fp)
{
  Tcp* tcp = (Tcp*)(pkt);
  fprintf(fp, "From IP address %x to TCP port %d\n", ntohl(ip4->ip_dst.s_addr), ntohs(tcp->th_dport));
}


inline void
log_udp_header(Ipv4* ip4, u_char const* pkt, FILE* fp)
{
  Udp* udp = (Udp*)(pkt);
  fprintf(fp, "From IP address %x to UDP port %d\n", ntohl(ip4->ip_dst.s_addr), ntohs(udp->uh_dport));
}


} // namespace

void
allowed_port_logger(u_char* udata, pcap_pkthdr const* pkthdr, u_char const* pkt)
{
  FILE* fp = fopen("allowed.txt", "a");

  int dl_len = (int) *udata;
  Ethernet* eth = (Ethernet*) (pkt);
  // If ipv4
  if (ntohs(eth->ether_type) == 0x800) {
    Ipv4* ip4 = (Ipv4*) (pkt + dl_len);
    // Calculate IP len
    int ip_len = ip4->ip_hl * 4;
    switch (ip4->ip_p) {
      case IPPROTO_TCP:
        log_tcp_header(ip4, pkt + dl_len + ip_len, fp);
        break;
      case IPPROTO_UDP:
        log_udp_header(ip4, pkt + dl_len + ip_len, fp);
        break;
    }
  }
  // TODO: If ipv6.

  // Close file.
  fclose(fp);
}


void
blocked_port_logger(u_char* udata, pcap_pkthdr const* pkthdr, u_char const* pkt)
{
  FILE* fp = fopen("allowed.txt", "a");

  int dl_len = (int) *udata;
  Ethernet* eth = (Ethernet*) (pkt);
  // If ipv4
  if (ntohs(eth->ether_type) == 0x800) {
    Ipv4* ip4 = (Ipv4*) (pkt + dl_len);
    // Calculate IP len
    int ip_len = ip4->ip_hl * 4;
    switch (ip4->ip_p) {
      case IPPROTO_TCP:
        log_tcp_header(ip4, pkt + dl_len + ip_len, fp);
        break;
      case IPPROTO_UDP:
        log_udp_header(ip4, pkt + dl_len + ip_len, fp);
        break;
    }
  }

  // TODO: If ipv6.

  // Close file.
  fclose(fp);
}


} // namespace bpf_test
