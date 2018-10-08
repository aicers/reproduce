#ifndef CONFIG_H
#define CONFIG_H

#include <string>

#include "util.h"

constexpr size_t QUEUE_SIZE_MIN = 1;
constexpr size_t QUEUE_SIZE_MAX = 900000;

enum class InputType {
  NONE,
  PCAP,
  PCAPNG,
  NIC,
  LOG,
};

enum class OutputType {
  NONE,
  KAFKA,
  FILE,
};

class Config {
public:
  // user
  bool mode_debug{false}; // print debug messages
  bool mode_eval{false};  // report statistics
  bool mode_grow{false};  // convert while tracking the growing file
  size_t count_skip{0};   // count to skip
  size_t queue_size{0};   // how many bytes send once
  size_t queue_period{0}; // how much time keep queued data
  std::string input;      // input: packet/log/none
  std::string output;     // output: kafka/file/none
  std::string packet_filter;
  std::string kafka_broker;
  std::string kafka_topic;
  std::string kafka_conf;

  // internal
  bool queue_auto{false};
  bool queue_defined{false};
  bool queue_flush{false};
  size_t count_send{0};
  size_t calculate_interval{0};
  InputType input_type;
  OutputType output_type;

  Config() = default;
  Config(const Config&) = default;
  Config& operator=(const Config&) = default;
  Config(Config&&) = default;
  Config& operator=(Config&&) = delete;
  ~Config() = default;
  bool set(int argc, char** argv);
  void show() const noexcept;

private:
  void help() const noexcept;
  void set_default() noexcept;
  void check() const;
};

#endif

// vim: et:ts=2:sw=2
