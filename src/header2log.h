#ifndef HEADER2LOG_H
#define HEADER2LOG_H

#include <cstdint>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

#include "conv.h"
#include "rdkafka_producer.h"

constexpr int PACKET_BUF_SIZE = 2048;

using bpf_int32 = int32_t;
using bpf_u_int32 = uint32_t;
using u_short = unsigned short;

struct pcap_file_header {
  bpf_u_int32 magic;
  u_short version_major;
  u_short version_minor;
  bpf_int32 thiszone;   /* gmt to local correction */
  bpf_u_int32 sigfigs;  /* accuracy of timestamps */
  bpf_u_int32 snaplen;  /* max length saved portion of each pkt */
  bpf_u_int32 linktype; /* data link type (LINKTYPE_*) */
};

struct pcap_timeval {
  bpf_int32 tv_sec;  /* seconds */
  bpf_int32 tv_usec; /* microseconds */
};

struct pcap_pkthdr {
  struct pcap_timeval ts; /* time stamp */
  bpf_u_int32 caplen;     /* length of portion present */
  bpf_u_int32 len;        /* length this packet (off wire) */
};

class Pcap : public Conv {
public:
  Pcap() = delete;
  Pcap(const std::string& filename);
  Pcap(const Pcap&) = delete;
  Pcap& operator=(const Pcap&) = delete;
  Pcap(Pcap&& other) noexcept;
  Pcap& operator=(const Pcap&&) = delete;
  ~Pcap();
  bool skip(size_t size) override;
  int get_next_stream(char* message, size_t size) override;

private:
  FILE* pcapfile;
  unsigned char packet_buf[PACKET_BUF_SIZE];
  char* ptr;
  unsigned int pcap_length;
  int stream_length;
  int length;
  uint32_t l2_type;
  uint16_t l3_type;
  uint8_t l4_type;
  int pcap_header_process();
  bool (Pcap::*get_l2_process())(unsigned char* offset);
  bool (Pcap::*get_l3_process())(unsigned char* offset);
  bool (Pcap::*get_l4_process())(unsigned char* offset);
  bool l2_ethernet_process(unsigned char* offset);
  bool l2_null_process(unsigned char* offset);
  bool l3_ipv4_process(unsigned char* offset);
  bool l3_arp_process(unsigned char* offset);
  bool l3_null_process(unsigned char* offset);
  bool l4_icmp_process(unsigned char* offset);
  bool l4_udp_process(unsigned char* offset);
  bool l4_tcp_process(unsigned char* offset);
  bool l4_null_process(unsigned char* offset);
  bool add_stream_length();
};

#endif

// vim: et:ts=2:sw=2
