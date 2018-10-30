#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <ctime>
#include <fstream>
#include <iostream>
#include <string>

#include <dirent.h>

#include <pcap/pcap.h>

#include "converter.h"
#include "producer.h"
#include "report.h"
#include "util.h"

enum class ControllerResult { Fail = -2, No_more = -1, Success = 0 };

class Controller {
public:
  Controller() = delete;
  Controller(Config);
  Controller(const Controller&) = delete;
  Controller& operator=(const Controller&) = delete;
  Controller(Controller&&) = delete;
  Controller& operator=(const Controller&&) = delete;
  ~Controller();
  void run();

private:
  std::shared_ptr<Config> conf;
  std::unique_ptr<Converter> conv;
  std::unique_ptr<Producer> prod;
  static pcap_t* pcd;
  FILE* pcapfile{nullptr};
  std::ifstream logfile;
  ControllerResult (Controller::*get_next_data)(char* imessage,
                                                size_t& imessage_len);
  bool (Controller::*skip_data)(const size_t count_skip);
  void run_split();
  void run_single();
  InputType get_input_type() const;
  OutputType get_output_type() const;
  bool set_converter();
  bool set_producer();
  uint32_t open_nic(const std::string& devname);
  void close_nic();
  uint32_t open_pcap(const std::string& filename);
  void close_pcap();
  void open_log(const std::string& filename);
  void close_log();
  ControllerResult get_next_nic(char* imessage, size_t& imessage_len);
  ControllerResult get_next_pcap(char* imessage, size_t& imessage_len);
  ControllerResult get_next_log(char* imessage, size_t& imessage_len);
  ControllerResult get_next_null(char* imessage, size_t& imessage_len);
  std::string get_next_file(DIR* dir) const;
  bool skip_pcap(const size_t count_skip);
  bool skip_log(const size_t count_skip);
  bool skip_null(const size_t count_skip);
  bool check_count(const size_t sent_count) const noexcept;
  static void signal_handler(int signal);
};

#endif

// vim: et:ts=2:sw=2