#include <iostream>
#include <unistd.h>

#include "config.h"
#include "util.h"

using namespace std;

static const char* program_name = "packetproducer";
static const char* default_broker = "localhost:9092";
static const char* default_topic = "pcap";
static constexpr size_t default_queue_size = 900000;
static constexpr size_t default_count = 1000000;

Config::Config(const bool& debug) { util.set_debug(debug); }

void Config::set_default() noexcept
{
  if (broker.empty()) {
    broker = default_broker;
  }

  if (topic.empty()) {
    topic = default_topic;
  }

  if (queue_size == 0) {
    queue_size = default_queue_size;
  }
}

bool Config::set(int argc, char** argv) noexcept
{
  int o;

  while ((o = getopt(argc, argv, "b:c:defhi:o:q:s:t:")) != -1) {
    switch (o) {
    case 'b':
      broker = optarg;
      break;
    case 'c':
      count_send = strtoul(optarg, nullptr, 0);
      break;
    case 'd':
      mode_debug = true;
      break;
    case 'e':
      mode_eval = true;
      break;
    case 'f':
      // TODO: not implemented yet
      filter = optarg;
      break;
    case 'h':
      help();
      return false;
    case 'i':
      // TODO: nic
      input = optarg;
      break;
    case 'o':
      output = optarg;
      break;
    case 'q':
      queue_size = strtoul(optarg, nullptr, 0);
      break;
    case 's':
      count_skip = strtoul(optarg, nullptr, 0);
      break;
    case 't':
      topic = optarg;
      break;
    default:
      break;
    }
  }

  set_default();
  show();

  return true;
}

void Config::help() const noexcept
{
  cout << "[USAGE] " << program_name << " OPTIONS\n";
  cout << "  -b: kafka broker"
       << " (default: " << default_broker << ")\n";
  cout << "  -c: send packet count\n";
  cout << "  -d: debug mode (print debug messages)\n";
  cout << "  -e: evaluation mode (report statistics)\n";
  cout << "  -f: tcpdump filter\n";
  cout << "  -h: help\n";
  cout << "  -i: input [PCAPFILE/LOGFILE/NIC/none(no specification)])\n";
  cout << "  -o: output [kafka(no specification)/TEXTFILE/none] (default: "
          "kafka)\n";
  cout << "  -q: queue byte (how many bytes send once)\n";
  cout << "  -s: skip packet count\n";
  cout << "  -t: kafka topic"
       << " (default: " << default_topic << ")\n";
}

void Config::show() const noexcept
{
  util.dprint(F, "mode_debug=", mode_debug);
  util.dprint(F, "mode_eval=", mode_eval);
  util.dprint(F, "count_send=", count_send);
  util.dprint(F, "count_skip=", count_skip);
  util.dprint(F, "queue_size=", queue_size);
  util.dprint(F, "input=", input);
  util.dprint(F, "output=", output);
  util.dprint(F, "filter=", filter);
  util.dprint(F, "broker=", broker);
  util.dprint(F, "topic=", topic);
}

// vim: et:ts=2:sw=2
