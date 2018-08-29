#ifndef CONVERTER_H
#define CONVERTER_H

#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

#include "producer.h"

/**
 * Converter
 */

enum class ConverterResult { FAIL = -2, NO_MORE = -1 };

class Converter {
public:
  virtual bool skip(size_t size) = 0;
  virtual int convert(char* message, size_t size) = 0;
};

/**
 * PacketConverter
 */

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

class PacketConverter : public Converter {
public:
  PacketConverter() = delete;
  PacketConverter(const std::string& filename);
  PacketConverter(const PacketConverter&) = delete;
  PacketConverter& operator=(const PacketConverter&) = delete;
  PacketConverter(PacketConverter&& other) noexcept;
  PacketConverter& operator=(const PacketConverter&&) = delete;
  ~PacketConverter();
  bool skip(size_t size) override;
  int convert(char* message, size_t size) override;

private:
  int conv_len = 0;
  FILE* pcapfile;
  unsigned char packet_buf[PACKET_BUF_SIZE];
  char* ptr;
  unsigned int pcap_length;
  int length;
  uint32_t l2_type;
  uint16_t l3_type;
  uint8_t l4_type;
  int pcap_header_process();
  bool (PacketConverter::*get_l2_process())(unsigned char* offset);
  bool (PacketConverter::*get_l3_process())(unsigned char* offset);
  bool (PacketConverter::*get_l4_process())(unsigned char* offset);
  bool l2_ethernet_process(unsigned char* offset);
  bool l2_null_process(unsigned char* offset);
  bool l3_ipv4_process(unsigned char* offset);
  bool l3_arp_process(unsigned char* offset);
  bool l3_null_process(unsigned char* offset);
  bool l4_icmp_process(unsigned char* offset);
  bool l4_udp_process(unsigned char* offset);
  bool l4_tcp_process(unsigned char* offset);
  bool l4_null_process(unsigned char* offset);
  bool add_conv_len();
};

/**
 * LogConverter
 */

class LogConverter : public Converter {
public:
  LogConverter() = delete;
  LogConverter(const std::string& filename);
  LogConverter(const LogConverter&) = delete;
  LogConverter& operator=(const LogConverter&) = delete;
  LogConverter(LogConverter&& other) noexcept;
  LogConverter& operator=(const LogConverter&&) = delete;
  ~LogConverter();
  bool skip(size_t count_skip) override;
  int convert(char* message, size_t size) override;

private:
  int conv_len = 0;
  std::ifstream logfile;
};

/**
 * NullConverter
 */

#endif

// vim: et:ts=2:sw=2
