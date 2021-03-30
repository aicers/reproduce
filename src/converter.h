#ifndef CONVERTER_H
#define CONVERTER_H

#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

struct ForwardMode;
struct Matcher;
struct Traffic;

extern "C" {

void matcher_free(Matcher* ptr);
auto matcher_match(Matcher* ptr, const char* data, size_t len) -> size_t;
auto matcher_new(const char* filename) -> Matcher*;
size_t traffic_data_len(const Traffic*);
void traffic_free(Traffic*);
void traffic_set_entropy_ratio(Traffic*, double);

} // extern "C"

namespace Conv {
enum class Status { Fail = -2, Pass = -1, Success = 0 };
}

/**
 * Converter
 */

class Converter {
public:
  virtual ~Converter() = default;
  virtual auto convert(uint64_t event_id, char* in, size_t in_len,
                       ForwardMode* pm) -> Conv::Status = 0;

  virtual auto get_matcher() -> Matcher* = 0;
  [[nodiscard]] virtual auto remaining_data() const -> bool = 0;
  virtual void set_allowed_entropy_ratio(float e) = 0;
  virtual void set_matcher(const std::string& filename) = 0;
};

/**
 * PacketConverter
 */

using bpf_int32 = int32_t;
using bpf_u_int32 = uint32_t;
using u_short = unsigned short;

struct pcap_timeval {
  bpf_int32 tv_sec;  /* seconds */
  bpf_int32 tv_usec; /* microseconds */
};

struct pcap_sf_pkthdr {
  struct pcap_timeval ts; /* time stamp */
  bpf_u_int32 caplen;     /* length of portion present */
  bpf_u_int32 len;        /* length this packet (off wire) */
};

class PacketConverter : public Converter {
public:
  PacketConverter() = delete;
  PacketConverter(const uint32_t _l2_type);
  PacketConverter(const PacketConverter&) = delete;
  auto operator=(const PacketConverter&) -> PacketConverter& = delete;
  PacketConverter(PacketConverter&&) = delete;
  auto operator=(const PacketConverter &&) -> PacketConverter& = delete;
  ~PacketConverter() override
  {
    traffic_free(traffic);
    matcher_free(matc);
  };
  auto convert(uint64_t event_id, char* in, size_t in_len, ForwardMode* msg)
      -> Conv::Status override;
  Matcher* get_matcher() override { return matc; }
  auto remaining_data() const -> bool override
  {
    return traffic_data_len(traffic) > 0;
  }
  void set_allowed_entropy_ratio(float e) override
  {
    traffic_set_entropy_ratio(traffic, e);
  }
  void set_matcher(const std::string& filename) override
  {
    matcher_free(matc);
    matc = matcher_new(filename.c_str());
  }

  auto payload_only_message(uint64_t event_id, ForwardMode* pm, const char* in,
                            size_t in_len) -> Conv::Status;

private:
  Matcher* matc{nullptr};
  Traffic* traffic{nullptr};
  bool match;
  uint32_t dst = 0;
  uint32_t ip_hl = 0;
  uint32_t l4_hl = 0;
  uint32_t l2_type;
  uint32_t src = 0;
  uint16_t dport = 0;
  uint16_t l3_type;
  uint16_t sport = 0;
  uint8_t l4_type;
  uint8_t proto = 0;
  uint8_t vlan = 0;

  auto get_l2_process()
      -> bool (PacketConverter::*)(unsigned char* offset, size_t length);
  auto get_l3_process()
      -> bool (PacketConverter::*)(unsigned char* offset, size_t length);
  auto get_l4_process()
      -> bool (PacketConverter::*)(unsigned char* offset, size_t length);

  auto l2_ethernet_process(unsigned char* offset, size_t length) -> bool;
  auto l2_null_process(unsigned char* offset, size_t length) -> bool;
  auto l3_ipv4_process(unsigned char* offset, size_t length) -> bool;
  auto l3_arp_process(unsigned char* offset, size_t length) -> bool;
  auto l3_null_process(unsigned char* offset, size_t length) -> bool;
  auto l4_icmp_process(unsigned char* offset, size_t length) -> bool;
  auto l4_udp_process(unsigned char* offset, size_t length) -> bool;
  auto l4_tcp_process(unsigned char* offset, size_t length) -> bool;
  auto l4_null_process(unsigned char* offset, size_t length) -> bool;
};

/**
 * LogConverter
 */

class LogConverter : public Converter {
public:
  LogConverter() = default;
  LogConverter(const LogConverter&) = delete;
  auto operator=(const LogConverter&) -> LogConverter& = delete;
  LogConverter(LogConverter&&) = delete;
  auto operator=(const LogConverter &&) -> LogConverter& = delete;
  ~LogConverter() override { matcher_free(matc); }
  auto convert(uint64_t event_id, char* in, size_t in_len, ForwardMode* msg)
      -> Conv::Status override;
  Matcher* get_matcher() override { return matc; }
  [[nodiscard]] bool remaining_data() const override { return false; }
  void set_allowed_entropy_ratio(float e) override {}
  void set_matcher(const std::string& filename) override
  {
    matcher_free(matc);
    matc = matcher_new(filename.c_str());
  }

private:
  Matcher* matc{nullptr};
};

#endif

// vim: et:ts=2:sw=2
