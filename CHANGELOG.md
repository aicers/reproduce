# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [0.21.2] - 2025-03-14

### Added

- Added a `log_dir` configuration to the common section.
  - If specified, logs will be written to a file named 'reproduce.log' in that
    directory.
  - If not specified, logs will be sent to stdout.
  - In debug mode, logs are always sent to stdout.
  - If `log_dir` is specified in debug mode, logs are sent to both stdout and
    the directory.

### Changed

- Extended report statistics to all log processing functions.
- Renamed the log file from reproduce.log to data_broker.log.

## [0.21.1] - 2025-01-25

### Changed

- Changed default empty value for zeek logs sent to "Datalake" to be the same as
  "Feature Sensor".

## [0.21.0] - 2024-11-25

### Added

- Added `sensor` field to `OpLog`.

### Removed

- Removed the deleted `source` within the `Netflow5`, `Netflow9`, `SecuLog`.

### Changed

- Changed `REQUIRED_GIGANTO_VERSION` to "0.23.0"

## [0.20.1] - 2024-10-22

### Fixed

- Fixed empty value of vector type from `vec![0]` to `Vec::new()` when sending
  Datelake export file.

### Changed

- Changed configuration field names.
  - `root` to `ca_certs` to handle multiple CA certs.
- Renamed `GIGANTO_VERSION` to `REQUIRED_GIGANTO_VERSION`.

## [0.20.0] - 2024-09-25

### Changed

- Updated the version of giganto-client to version 0.20.0. Updating to this
  version results in the following changes.
  - Updated the version of quinn, rustls from 0.10, 0.21 to 0.11, 0.23. With the
    update to this version, the usage of the quinn and rustls crates has
    changed, so code affected by the update has also been modified.
  - Modified parsing code in zeek log and giganto log due to changes in conn,
    http, smtp, ntlm, ssh, tls protocol fields.
  - Support for sending `giganto` log for new protocols. (`Bootp`,`Dhcp`).
  - Changed `GIGANTO_VERSION` to "0.21.0"
- Change to send events in unit of 100 for protocol events.
- Applied code import ordering by `StdExternalCrate`. From now on, all code is
  expected to be formatted using `cargo fmt -- --config group_imports=StdExternalCrate`.

## [0.19.0] - 2024-05-14

### Changed

- Change to read all command line parameters in config toml file.
  - Removes the option to start from a specific line (`-f`), since skip
    lines also allow sending from a specific line.
  - Modify the skip count/send count/last sent line options(`-s`/`-c`/`-r`),
    which only worked with logs, to work with all conditions.
  - Modify it so that folder polling is applied first.
  - Remove the option for output type.(`-o`) The associated functionality
    is now deprecated.
- Changed configuration field names.
  - `roots` to `root` to handle using a single root.
  - `giganto_ingest_addr` to `giganto_ingest_srv_addr`.

## [0.18.0] - 2024-01-25

### Added

- Added function to send sysmon events from elastic search.
  - input: elastic
  - `-E` option needed for elastic search.
  - Added elastic search configuration fields to config file.

### Changed

- Modified netflow event according to giganto-client.
- Modified config file

## [0.17.5] - 2023-11-09

### Added

- Supports Security logs, See details in README.

## [0.17.4] - 2023-10-23

### Added

- Supports `Netflow5`, `Netflow9` pcap.

### Changed

- Modified kerberos event to support giganto-client.

## [0.17.3] - 2023-08-23

### Added

- Added the line number to convert error message.
- Supports sysmon csv log.
  - kind:
    "process_create",
    "file_create_time",
    "network_connect",
    "process_terminate",
    "image_load",
    "file_create",
    "registry_value_set",
    "registry_key_rename",
    "file_create_stream_hash",
    "pipe_event",
    "dns_query",
    "file_delete",
    "process_tamper",
    "file_delete_detected"

### Changed

- Replaced `lazy_static` with the new `std::sync::OnceLock`.

## [0.17.2] - 2023-07-11

### Added

- Added a list of supported protocols to `GIGANTO_ZEEK_KINDS`.

### Changed

- Changed the output option's default value to "giganto".
- Changed the input option to required option.

### Removed

- Removed unused confd files.

## [0.17.1] - 2023-07-10

### Added

- Support for sending `giganto` log for new protocols. (`mqtt`).

## [0.17.0] - 2023-07-04

### Added

- Support for sending `giganto` log for new protocols. (`smb`, `nfs`).
  For `nfs`, zeek log does not exist, and for `smb`, the protocol generates
  multiple types of logs (conn.log/kerberos.log/smb_files.log, etc.), So it
  only supports sending Giganto's log files.

## [0.16.0] - 2023-06-27

### Changed

- Support for extended `struct Http`.
  - `orig_filenames: Vec<String>`
  - `orig_mime_types: Vec<String>`
  - `resp_filenames: Vec<String>`
  - `resp_mime_types: Vec<String>`

### Added

- Support for sending `giganto`/`zeek` log for new protocols.
  (`ldap`, `tls`, `ftp`). The structure of `Tls` was defined based on the field
  values sent by aicer's packet extraction program. As a result, many fields
  will be insufficient when transmitted by conventional `zeek log`(ssl.log),
  and the insufficient fields will be filled with the default value("-"/0) and
  transmitted.

## [0.15.0] - 2023-05-18

### Changed

- Modified to only send giganto-version during handshake process by removing
  ‘-reproduce’ because the agent name is included in the certificate.
- Bump giganto-client, quinn, rustls to latest version.

## [0.14.0] - 2023-03-30

### Added

- Add ctrlc for zeeklog and oplog when the grow option is given.
- Add common field (5-tuple + duration)
- Add additional `-m` options with giganto export file

### Changed

- Change `duration` field name to `last_time`. (Except Session struct)

### Removed

- Dropped Kafka server support.

## [0.13.0] - 2023-01-04

### Added

- Send zeek conn, http, rdp, smtp to giganto with kind option
  `"conn", "http", "rdp", "smtp", "ntlm", "kerberos"`
  `"ssh", "dce_rpc"`
- Add zeeklog skip option
  `-f` option read line from given line number (at least 1),
- Send operation log to giganto with kind option
  `"oplog"`

### Changed

- `-g` grow option uses alone; doesn't take true or false no more.

### Deprecated

- Deprecated Kafka server.

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

[0.21.2]: https://github.com/aicers/reproduce/compare/0.21.1...0.21.2
[0.21.1]: https://github.com/aicers/reproduce/compare/0.21.0...0.21.1
[0.21.0]: https://github.com/aicers/reproduce/compare/0.20.1...0.21.0
[0.20.1]: https://github.com/aicers/reproduce/compare/0.20.0...0.20.1
[0.20.0]: https://github.com/aicers/reproduce/compare/0.19.0...0.20.0
[0.19.0]: https://github.com/aicers/reproduce/compare/0.18.0...0.19.0
[0.18.0]: https://github.com/aicers/reproduce/compare/0.17.5...0.18.0
[0.17.5]: https://github.com/aicers/reproduce/compare/0.17.4...0.17.5
[0.17.4]: https://github.com/aicers/reproduce/compare/0.17.3...0.17.4
[0.17.3]: https://github.com/aicers/reproduce/compare/0.17.2...0.17.3
[0.17.2]: https://github.com/aicers/reproduce/compare/0.17.1...0.17.2
[0.17.1]: https://github.com/aicers/reproduce/compare/0.17.0...0.17.1
[0.17.0]: https://github.com/aicers/reproduce/compare/0.16.0...0.17.0
[0.16.0]: https://github.com/aicers/reproduce/compare/0.15.0...0.16.0
[0.15.0]: https://github.com/aicers/reproduce/compare/0.14.0...0.15.0
[0.14.0]: https://github.com/aicers/reproduce/compare/0.13.0...0.14.0
[0.13.0]: https://github.com/aicers/reproduce/compare/0.12.0...0.13.0
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
