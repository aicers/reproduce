# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Send zeek conn, http, rdp, smtp to giganto with kind option
  `"conn", "http", "rdp", "smtp", "ntlm", "kerberos"`
  `"ssh", "dce_rpc"`
- Add zeeklog skip option
  `-f` option read line from given line number (at least 1),
- Send operation log to giganto with kind option
  `"oplog"`

### Changed

- `-g` grow option uses alone; doesn't take true or false

## [0.12.0] - 2022-11-02

### Changed

- Send line to line when giganto connected

## [0.11.0] - 2022-10-05

### Added

- Support for x86_64-unknown-linux-musl.
- Support Giganto server.
  `-o "giganto" -C "tests/config.toml"` to test
  `-G` option to set giganto server address (default: 127.0.0.1:38370)
  `-N` option is giganto server name, (default: localhost)
  `-C` option is certificate path toml file
  `-k` option to set log kind to giganto, like topic of Kafka

  ```toml
  [certification]
  cert = "tests/cert.pem"
  key = "tests/key.pem"
  roots = ["tests/root.pem"]
  ```

- Protocol version check before send log.
- Added termination logic for one-shot req/resp to giganto.

### Removed

- Dropped support for packets. Run zeek and read its log files instead.
- Dropped Docker support. Instead, instructions to build a portable binary was
  added to README.

## [0.10.0] - 2021-06-11

### Added

- `-V` option to display the version number.

### Changed

- librdkafka is no longer needed.
- An invalid command-line option value is not converted into the default value;
  instead it results in an error.
- No longer requires OpenSSL.

## [0.9.10] - 2020-09-08

### Changed

- "event_id = time(32bit) + serial-number(24bit) + data-origin(8bit)"
  The "time" is current time of system, and "data-origin" is attached also.
  And "serial-number" is rotating from 0 to max 24bit number.

  The value of "event_id" is not continuous because of this.

  If REPRODUCE finishes processing 24bit events within 1 second (ie, before the
  "time" value is changed), the serial number starts from 0 again, so the
  "event_id" that follows is less than the "event_id" of the previous event.

  Patch: the "event_id" created later has a larger value than before, at all time.

## [0.9.9] - 2020-06-17

### Changed

- modify magic code to identify pcap-ng
- modify code to send pcap-ng pcap file
- follow what ClangTidy says. destroy c++11 warnings

## [0.9.8] - 2020-04-29

### Changed

- "event_id" format is changed.
- previous format: event_id(64bit) = datasource id(upper 16bit) + sequence
  number(lower 48bit)
- new format: event_id(64bit) = current system time in seconds(upper 32bit) +
  sequence number (lower 24bit) + datasource id(lowest 8bit)

## [0.9.7] - 2020-04-08

### Added

- Add '-j' option: user can set the initial event_id number. Without this
  option, event_id will be begin at 1 or skip_count+1.
- Add '-v' option: REproduce watches the input directory and sends it when new
  files are found.
- Instead of the name 'report.txt', use the Kafka topic name as the file name.

### Fixed

- The default value of `message.timeout.ms` is set to 5,000 ms, the default
  value of `linger.ms`. This allows to link REproduce against librdkafka>=1.0.

## [0.9.6] - 2019-07-22

### Changed

- (test) For PCAP, this version wil send payload only rather than session +
  payload 2KB. And sessions.txt does not created.
- Produce success messages are displayed in every 100 success, i.e., around
  100MB sent.

## [0.9.5] - 2019-07-12

### Changed

- 'report.txt', 'session.txt' file name changed to `report.txt-YYYYMMDDHHMMSS`
  and `sessions.txt-YYYYMMDDHHMMSS`
- bug fixed: event_id for TCP, UDP, ICMP is still session number. it's fixed to
  send packet number.

## [0.9.4] - 2019-07-10

### Added

- When REproduce send PCAP, it will save session information into
  `/report/sessions.txt` file. If the '/report' directory does not exist,
  REproduce will try to open in the current directory where REproduce is running
  in. The session information is appended at the end of the file. You should
  clear it before REproduce run if you want to get clean data.

## [0.9.3] - 2019-07-08

### Changed

- The event_id for pcap changed to the number of packets read from that PCAP file.
  In previous version event_id was session number.
- `report.txt` file will be created in `/report/` directory if it is exist, like
  `/report/report.txt`. If not, REproduce will try to open in the current
  directory where REproduce is running in. If you want to run REproduce in
  Docker, you should bind the `/report` to see the report file from the host.
- Dockerfile changed to use g++-8

[Unreleased]: https://github.com/aicers/reproduce/compare/0.12.0...main
[0.12.0]: https://github.com/aicers/reproduce/compare/0.11.0...0.12.0
[0.11.0]: https://github.com/aicers/reproduce/compare/0.10.0...0.11.0
[0.10.0]: https://github.com/aicers/reproduce/compare/0.9.10...0.10.0
[0.9.10]: https://github.com/aicers/reproduce/compare/0.9.9...0.9.10
[0.9.9]: https://github.com/aicers/reproduce/compare/0.9.8...0.9.9
[0.9.8]: https://github.com/aicers/reproduce/compare/0.9.7...0.9.8
[0.9.7]: https://github.com/aicers/reproduce/compare/0.9.6...0.9.7
[0.9.6]: https://github.com/aicers/reproduce/compare/0.9.5...0.9.6
[0.9.5]: https://github.com/aicers/reproduce/compare/0.9.4...0.9.5
[0.9.4]: https://github.com/aicers/reproduce/compare/0.9.3...0.9.4
[0.9.3]: https://github.com/aicers/reproduce/compare/0.9.2...0.9.3
