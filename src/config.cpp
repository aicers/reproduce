#include <iostream>
#include <unistd.h>

#include "config.h"

using namespace std;

static constexpr char PROGRAM_NAME[] = "packetproducer";
static constexpr char PROGRAM_VERSION[] = "0.1.0";
static constexpr char default_kafka_broker[] = "localhost:9092";
static constexpr char default_kafka_topic[] = "pcap";
static constexpr char default_kafka_conf[] = "kafka.conf";
static constexpr size_t default_queue_size = 900000;

void Config::help() const noexcept
{
  cout << PROGRAM_NAME << "-" << PROGRAM_VERSION << "\n";
  cout << "[USAGE] " << PROGRAM_NAME << " [OPTIONS]\n";
  cout << "  -b: kafka broker list"
       << " (default: " << default_kafka_broker << ")\n";
  cout << "  -c: send count\n";
  cout << "  -d: debug mode. print debug messages\n";
  cout << "  -e: evaluation mode. report statistics\n";
  cout << "  -f: tcpdump filter (when input is PCAP or NIC)\n";
  cout << "  -h: help\n";
  cout << "  -i: input [PCAPFILE/LOGFILE/NIC]\n";
  cout << "      If no 'i' option is given, sample data is converted\n";
  cout << "  -k: kafka config file"
       << " (default: " << default_kafka_conf << ")\n";
  cout << "  -o: output [TEXTFILE/none]\n";
  cout << "      If no 'o' option is given, it will be sent via kafka\n";
  cout << "  -q: queue size in byte. how many bytes send once"
       << " (default: " << default_queue_size << ")\n";
  cout << "  -s: skip count\n";
  cout << "  -t: kafka topic"
       << " (default: " << default_kafka_topic << ")\n";
}

bool Config::set(int argc, char** argv)
{
  int o;
  while ((o = getopt(argc, argv, "b:c:defhi:k:o:q:s:t:")) != -1) {
    switch (o) {
    case 'b':
      kafka_broker = optarg;
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
      packet_filter = optarg;
      break;
    case 'h':
      help();
      return false;
    case 'i':
      // TODO: nic
      input = optarg;
      break;
    case 'k':
      kafka_conf = optarg;
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
      kafka_topic = optarg;
      break;
    default:
      break;
    }
  }

  Util::set_debug(mode_debug);

  set_default();
  show();
  check();

  return true;
}

void Config::set_default() noexcept
{
  Util::dprint(F, "set default config");

  if (kafka_broker.empty()) {
    kafka_broker = default_kafka_broker;
  }

  if (kafka_topic.empty()) {
    kafka_topic = default_kafka_topic;
  }

  if (kafka_conf.empty()) {
    kafka_conf = default_kafka_conf;
  }

  if (queue_size == 0) {
    queue_size = default_queue_size;
  }
}

void Config::check() const
{
  Util::dprint(F, "check config");

  if (input.empty() && output == "none") {
    throw runtime_error("You must specify input(-i) or output(-o) is not none");
  }

  // and so on...
}

void Config::show() const noexcept
{
  Util::dprint(F, "mode_debug=", mode_debug);
  Util::dprint(F, "mode_eval=", mode_eval);
  Util::dprint(F, "count_send=", count_send);
  Util::dprint(F, "count_skip=", count_skip);
  Util::dprint(F, "queue_size=", queue_size);
  Util::dprint(F, "input=", input);
  Util::dprint(F, "output=", output);
  Util::dprint(F, "packet_filter=", packet_filter);
  Util::dprint(F, "kafka_broker=", kafka_broker);
  Util::dprint(F, "kafka_topic=", kafka_topic);
  Util::dprint(F, "kafka_conf=", kafka_conf);
}

// vim: et:ts=2:sw=2
