#include <iostream>
#include <sys/stat.h>

#include "report.h"

using namespace std;

static constexpr double KBYTE = 1024.0;
static constexpr double MBYTE = KBYTE * KBYTE;
static constexpr double KPACKET = 1000.0;
static constexpr double MPACKET = KPACKET * KPACKET;

Report::Report(shared_ptr<Config> _conf) : conf(move(_conf)) {}

void Report::start() noexcept
{
  if (!conf->mode_eval) {
    return;
  }

  time_start = clock();
}

void Report::process(const size_t orig_length,
                     const size_t sent_length) noexcept
{
  if (orig_length > orig_byte_max) {
    orig_byte_max = orig_length;
  } else if (orig_length < orig_byte_min || orig_byte_min == 0) {
    orig_byte_min = orig_length;
  }
  orig_byte += orig_length;

  if (sent_length > sent_byte_max) {
    sent_byte_max = sent_length;
  } else if (sent_length < sent_byte_min || sent_byte_min == 0) {
    sent_byte_min = sent_length;
  }
  sent_byte += sent_length;

  sent_count++;
}

void Report::end() noexcept
{
  if (!conf->mode_eval) {
    return;
  }

  time_now = clock();
  time_diff = static_cast<double>(time_now - time_start) / CLOCKS_PER_SEC;

  if (time_diff) {
    perf_kbps = static_cast<double>(sent_byte) / KBYTE / time_diff;
    perf_kpps = static_cast<double>(sent_count) / KPACKET / time_diff;
  }
  if (sent_count) {
    orig_byte_avg = static_cast<double>(orig_byte) / sent_count;
    sent_byte_avg = static_cast<double>(sent_byte) / sent_count;
  }

  cout.precision(2);
  cout << fixed;
  cout << "--------------------------------------------------\n";
  struct stat st;
  switch (conf->input_type) {
  case InputType::PCAP:
    cout << "Input(PCAP)\t: " << conf->input;
    if (stat(conf->input.c_str(), &st) != -1) {
      cout << "(" << static_cast<double>(st.st_size) / MBYTE << "M)\n";
    } else {
      cout << '\n';
    }
    break;
  case InputType::LOG:
    cout << "Input(LOG)\t: " << conf->input;
    if (stat(conf->input.c_str(), &st) != -1) {
      cout << "(" << static_cast<double>(st.st_size) / MBYTE << "M)\n";
    } else {
      cout << '\n';
    }
    break;
  case InputType::NONE:
    cout << "Input(NONE)\t: \n";
    break;
  default:
    break;
  }
  switch (conf->output_type) {
  case OutputType::FILE:
    cout << "Output(FILE)\t: " << conf->output;
    if (stat(conf->input.c_str(), &st) != -1) {
      cout << "(" << static_cast<double>(st.st_size) / MBYTE << "M)\n";
    } else {
      cout << "(invalid)\n";
    }
    break;
  case OutputType::KAFKA:
    cout << "Output(KAFKA)\t: " << conf->kafka_broker << "("
         << conf->kafka_topic << ")\n";
    break;
  case OutputType::NONE:
    cout << "Output(NONE)\t: \n";
    break;
  }
  cout << "Input Length\t: " << orig_byte_min << "/" << orig_byte_max << "/"
       << orig_byte_avg << "(Min/Max/Avg)\n";
  cout << "Output Length\t: " << sent_byte_min << "/" << sent_byte_max << "/"
       << sent_byte_avg << "(Min/Max/Avg)\n";
  cout << "Sent Bytes\t: " << sent_byte << "("
       << static_cast<double>(sent_byte) / MBYTE << "M)\n";
  cout << "Sent Count\t: " << sent_count << "("
       << static_cast<double>(sent_count) / MPACKET << "M)\n";
  cout << "Fail Count\t: " << fail_count << "("
       << static_cast<double>(fail_count) / MPACKET << "M)\n";
  cout << "Elapsed Time\t: " << time_diff << "s\n";
  cout << "Performance\t: " << perf_kbps / KBYTE << "MBps/" << perf_kpps
       << "Kpps\n";
  cout << "--------------------------------------------------\n";
}

void Report::fail() noexcept { fail_count++; }

size_t Report::get_sent_count() const noexcept { return sent_count; }

// vim: et:ts=2:sw=2
