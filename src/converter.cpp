#include <arpa/inet.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <functional>
#include <iomanip>
#include <memory>
#include <stdexcept>

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "ipv4.h"
#include "service.h"
#include "tcp.h"
#include "udp.h"

#include "converter.h"

using namespace std;

/**
 * PacketConverter
 */

#define ADD_STREAM(args...)                                                    \
  if ((length = sprintf(ptr, ##args)) < 0) {                                   \
    return false;                                                              \
  }                                                                            \
  ptr += length;                                                               \
  conv_len += length;

PacketConverter::PacketConverter(const uint32_t _l2_type) : l2_type(_l2_type) {}

size_t PacketConverter::convert(char* in, size_t in_len, char* out,
                                size_t out_len)
{
  // TODO: How to check the bounds of the buffer?
  conv_len = 0;
  ptr = out;
  auto* pp = reinterpret_cast<pcap_pkthdr*>(in);

#if 0
  // TODO: Fix to enhance performance
  char* cap_time = nullptr;
  cap_time = (char*)ctime((const time_t*)&sec);
  cap_time[strlen(cap_time) - 1] = '\0';
#endif

  ADD_STREAM("%d ", pp->ts.tv_sec);

  if (!invoke(get_l2_process(), this,
              reinterpret_cast<unsigned char*>(in + sizeof(pcap_pkthdr)))) {
    return 0;
  }

  // TODO: payload process

  return conv_len;
}

bool (PacketConverter::*PacketConverter::get_l2_process())(
    unsigned char* offset)
{
  switch (l2_type) {
  case 1:
    return &PacketConverter::l2_ethernet_process;
  default:
    break;
  }

  return &PacketConverter::l2_null_process;
}

bool (PacketConverter::*PacketConverter::get_l3_process())(
    unsigned char* offset)
{
  switch (l3_type) {
  case ETHERTYPE_IP:
    return &PacketConverter::l3_ipv4_process;
  case ETHERTYPE_ARP:
    return &PacketConverter::l3_arp_process;
  default:
    break;
  }

  return &PacketConverter::l3_null_process;
}

bool (PacketConverter::*PacketConverter::get_l4_process())(
    unsigned char* offset)
{
  switch (l4_type) {
  case IPPROTO_ICMP:
    return &PacketConverter::l4_icmp_process;
  case IPPROTO_TCP:
    return &PacketConverter::l4_tcp_process;
  case IPPROTO_UDP:
    return &PacketConverter::l4_udp_process;
  default:
    break;
  }

  return &PacketConverter::l4_null_process;
}

bool PacketConverter::l2_ethernet_process(unsigned char* offset)
{
  auto eh = reinterpret_cast<ether_header*>(offset);

  offset += sizeof(struct ether_header);

  ADD_STREAM(
      "Ethernet2 %02x:%02x:%02x:%02x:%02x:%02x %02x:%02x:%02x:%02x:%02x:%02x ",
      (eh->ether_dhost)[0], (eh->ether_dhost)[1], (eh->ether_dhost)[2],
      (eh->ether_dhost)[3], (eh->ether_dhost)[4], (eh->ether_dhost)[5],
      (eh->ether_shost)[0], (eh->ether_shost)[1], (eh->ether_shost)[2],
      (eh->ether_shost)[3], (eh->ether_shost)[4], (eh->ether_shost)[5]);

  l3_type = htons(eh->ether_type);
  if (!invoke(get_l3_process(), this, offset)) {
    return false;
  }

  return true;
}

bool PacketConverter::l3_ipv4_process(unsigned char* offset)
{
  auto iph = reinterpret_cast<ip*>(offset);
  size_t opt = 0;
  offset += sizeof(IP_MINLEN);

  ADD_STREAM("IP %d %d %d %d %d %d %d %d %u.%u.%u.%u %u.%u.%u.%u ",
             IP_V(iph->ip_vhl), IP_HL(iph->ip_vhl), iph->ip_tos, iph->ip_len,
             iph->ip_id, iph->ip_off, iph->ip_ttl, iph->ip_sum, iph->ip_src[0],
             iph->ip_src[1], iph->ip_src[2], iph->ip_src[3], iph->ip_dst[0],
             iph->ip_dst[1], iph->ip_dst[2], iph->ip_dst[3]);

  opt = IP_HL(iph->ip_vhl) * 4 - sizeof(IP_MINLEN);
  if (opt != 0) {
    offset += opt;
    ADD_STREAM("%s ", "ip_opt");
  }

  l4_type = iph->ip_p;
  if (!invoke(get_l4_process(), this, offset)) {
    return false;
  }

  return true;
}

bool PacketConverter::l3_arp_process(unsigned char* offset)
{
  auto arph = reinterpret_cast<arp_pkthdr*>(offset);
  uint16_t hrd = 0, pro = 0;
  offset += sizeof(arph);
  hrd = htons(arph->ar_hrd);
  pro = htons(arph->ar_pro);

  ADD_STREAM("ARP %s %s ", arpop_values.find(hrd)->second,
             ethertype_values.find(pro)->second);

  if ((pro != ETHERTYPE_IP && pro != ETHERTYPE_TRAIL) || arph->ar_pln != 4 ||
      arph->ar_hln != 6) {
    ADD_STREAM("%s ", "Unknown_ARP(HW_ADDR)");
    return true;
  }

  unsigned char* eth_sha = offset;
  offset += arph->ar_hln;
  unsigned char* ip_spa = offset;
  offset += arph->ar_pln;
  unsigned char* eth_tha = offset;
  offset += arph->ar_hln;
  unsigned char* ip_tpa = offset;

  switch (htons(arph->ar_op)) {
  case ARPOP_REQUEST:
    ADD_STREAM("who-has %u.%u.%u.%u tell %u.%u.%u.%u ", ip_tpa[0], ip_tpa[1],
               ip_tpa[2], ip_tpa[3], ip_spa[0], ip_spa[1], ip_spa[2],
               ip_spa[3]);
    break;
  case ARPOP_REPLY:
    ADD_STREAM("%u.%u.%u.%u is-at %02x:%02x:%02x:%02x:%02x:%02x ", ip_spa[0],
               ip_spa[1], ip_spa[2], ip_spa[3], eth_sha[0], eth_sha[1],
               eth_sha[2], eth_sha[3], eth_sha[4], eth_sha[5]);
    break;
  case ARPOP_REVREQUEST:
    ADD_STREAM("who-is %02x:%02x:%02x:%02x:%02x:%02x tell "
               "%02x:%02x:%02x:%02x:%02x:%02x ",
               eth_tha[0], eth_tha[1], eth_tha[2], eth_tha[3], eth_tha[4],
               eth_tha[5], eth_tha[0], eth_sha[1], eth_sha[2], eth_sha[3],
               eth_sha[4], eth_sha[5]);
    break;
  case ARPOP_REVREPLY:
    ADD_STREAM("%02x:%02x:%02x:%02x:%02x:%02x at %u.%u.%u.%u ", eth_tha[0],
               eth_tha[1], eth_tha[2], eth_tha[3], eth_tha[4], eth_tha[5],
               ip_tpa[0], ip_tpa[1], ip_tpa[2], ip_tpa[3]);
    break;
  case ARPOP_INVREQUEST:
    ADD_STREAM("who-is %02x:%02x:%02x:%02x:%02x:%02x tell "
               "%02x:%02x:%02x:%02x:%02x:%02x ",
               eth_tha[0], eth_tha[1], eth_tha[2], eth_tha[3], eth_tha[4],
               eth_tha[5], eth_tha[0], eth_sha[1], eth_sha[2], eth_sha[3],
               eth_sha[4], eth_sha[5]);
    break;
  case ARPOP_INVREPLY:
    ADD_STREAM("%02x:%02x:%02x:%02x:%02x:%02x at %u.%u.%u.%u ", eth_sha[0],
               eth_sha[1], eth_sha[2], eth_sha[3], eth_sha[4], eth_sha[5],
               ip_spa[0], ip_spa[1], ip_spa[2], ip_spa[3]);
    break;
  default:
    break;
  }

  return true;
}

bool PacketConverter::l2_null_process(unsigned char* offset)
{
  ADD_STREAM("Unknown_L2(%d) ", l2_type);

  return true;
}

bool PacketConverter::l3_null_process(unsigned char* offset)
{
  ADD_STREAM("Unknown_L3(%d) ", l3_type);

  return true;
}

bool PacketConverter::l4_null_process(unsigned char* offset)
{
  ADD_STREAM("Unknown_L4(%d) ", l4_type);

  return true;
}

bool PacketConverter::l4_tcp_process(unsigned char* offset)
{
  auto tcph = reinterpret_cast<tcphdr*>(offset);

#if 0
  // FIXME: option & payload processing
  offset += TCP_MINLEN;
#endif

  ADD_STREAM(
      "TCP %d %d %u %u %d %s%s%s%s%s%s %d %d %d ", ntohs(tcph->th_sport),
      ntohs(tcph->th_dport), ntohl(tcph->th_seq), ntohl(tcph->th_ack),
      TCP_HLEN(tcph->th_offx2) * 4, tcph->th_flags & TH_URG ? "U" : "",
      tcph->th_flags & TH_ACK ? "A" : "", tcph->th_flags & TH_PUSH ? "P" : "",
      tcph->th_flags & TH_RST ? "R" : "", tcph->th_flags & TH_SYN ? "S" : "",
      tcph->th_flags & TH_FIN ? "F" : "", ntohs(tcph->th_win),
      ntohs(tcph->th_sum), tcph->th_urp);

#if 0
  // TODO: Fix performance problem
  uint16_t service = static_cast<uint16_t>(
      min(min(ntohs(tcph->th_sport), ntohs(tcph->th_dport)),
        MAX_DEFINED_PORT_NUMBER));
  if (service < MAX_DEFINED_PORT_NUMBER)
    ADD_STREAM("%s ", TCP_PORT_SERV_DICT.find(service)->second);
#endif

  return true;
}

bool PacketConverter::l4_udp_process(unsigned char* offset)
{
  auto udph = reinterpret_cast<udphdr*>(offset);

#if 0
  // FIXME: payload processing
  offset += sizeof(struct udphdr);
#endif

  ADD_STREAM("UDP %d %d %d %d ", ntohs(udph->uh_sport), ntohs(udph->uh_dport),
             ntohs(udph->uh_ulen), ntohs(udph->uh_sum));

  return true;
}

bool PacketConverter::l4_icmp_process(unsigned char* offset)
{
  auto icmph = reinterpret_cast<icmp*>(offset);

#if 0
  // FIXME: more header processing
  offset += ICMP_MINLEN;
#endif

  if ((unsigned int)(icmph->icmp_type) == 11) {
    ADD_STREAM("ICMP %d %d %d %s ", icmph->icmp_type, icmph->icmp_code,
               icmph->icmp_cksum, "ttl_expired");
  } else if ((unsigned int)(icmph->icmp_type) == ICMP_ECHOREPLY) {
    ADD_STREAM("ICMP %d %d %d %s ", icmph->icmp_type, icmph->icmp_code,
               icmph->icmp_cksum, "echo_reply");
  }

  return true;
}

/**
 * LogConverter
 */

size_t LogConverter::convert(char* in, size_t in_len, char* out, size_t out_len)
{
  if (in == nullptr) {
    return 0;
  }

  if (in_len < out_len) {
    memcpy(out, in, in_len);
    return in_len;
  } else {
    memcpy(out, in, out_len);
    return out_len;
  }
}

/**
 * NullConverter
 */

size_t NullConverter::convert(char* in, size_t in_len, char* out,
                              size_t out_len)
{
  memcpy(out, in, in_len + 1);

  return in_len;
}

// vim: et:ts=2:sw=2
