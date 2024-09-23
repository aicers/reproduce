# REproduce

REproduce monitors a log file or a directory of log files, and sends appended
entries to a Giganto server.

[![Coverage Status](https://codecov.io/gh/aicers/reproduce/branch/main/graph/badge.svg?token=2P7VSZ1KFV)](https://codecov.io/gh/aicers/reproduce)

## Requirements

* Giganto 0.14.0.

## Build

REproduce may be built as a static binary for portability. Make sure that the
musl target is available. On Ubuntu-based systems, you will need to install the
`musl-tools` package, which provides the musl-gcc compiler required by some
dependencies:

```sh
sudo apt install musl-tools
```

Then, install the Rust compiler for `x86_64-unknown-linux-musl` if it is not
already installed:

```sh
rustup target add x86_64-unknown-linux-musl
```

The portable static REproduce binary, `reproduce`, can be created with the
following command:

```sh
cargo build --target x86_64-unknown-linux-musl --release
```

The compiled binary will be created in
`target/x86_64-unknown-linux-musl/release`.

## Usage

To diplay the usage, type:

```sh
reproduce -h
```

To support pcap parser for netflow v9, templates would be read from
the environment variable `NETFLOW_TEMPLATES_PATH`.

## Examples

* Information about all config fields is as follows

  ```toml
  [common]
  cert = "tests/cert.pem"                  # Path to private key file.
  key = "tests/key.pem"                    # Path to certificate file.
  root = "tests/root.pem"                  # Path to CA certificate file.
  giganto_ingest_srv_addr = "127.0.0.1:38370"  # Address of the giganto ingest.
  giganto_name = "aicers"                  # Giganto server name.
  kind ="http"                             # Data kind. Default is empty string.
  input = "/path/to/file_or_directory"     # Input type. (file/directory/"elastic")
  report = false             # Flag for transfer stats report. Default is false.

  [file]
  export_from_giganto = true # Giganto export file type flag. Default is false.
  polling_mode = false              # File polling mode flag. Default is false.
  transfer_count = 0                       # The number of line/packet to sent.
  transfer_skip_count = 0                  # The number of line/packet to skip.
  last_transfer_line_suffix = "bck"        # A suffix string for the new file
                                           # where info about the last transfer
                                           # line will be stored.

  [directory]
  file_prefix = "http"                     # Prefix of the file name.
  polling_mode = false        # Directory polling mode flag. Default is false.

  [elastic]
  url = "http://127.0.0.1:9200/"               # Elasticsearch server url.
  event_codes = ["1","7","11","17","25","26",] # Target event kind
  indices = [".ds-winlogbeat-8.8.2-2023.11.29-000001"]  # elasticsearch index.
  start_time = "2023-08-06T15:00:00.000Z"      # Target start/end time.
  end_time = "2023-09-07T02:00:00.000Z"
  size = 100000                                # Fetch size.
  dump_dir = "tests/dump"                      # Csv dump path.
  elastic_auth = "admin:admin"                 # Elastic auth info. (id/pw)
  ```

* Convert a zeek log file and send it to Giganto server:

  ```toml
  [common]
  cert = "tests/cert.pem"
  key = "tests/key.pem"
  root = "tests/root.pem"
  giganto_ingest_srv_addr = "127.0.0.1:38370"
  giganto_name = "aicers"
  kind ="dns"                                # kind in `Network Events` at the bottom.
  input = "/path/to/zeek_file"
  ```

* Send operation log to Giganto server:

  ```toml
  [common]
  cert = "tests/cert.pem"
  key = "tests/key.pem"
  root = "tests/root.pem"
  giganto_ingest_srv_addr = "127.0.0.1:38370"
  giganto_name = "aicers"
  kind ="oplog"                              # Use a fixed kind value.
  input = "/path/to/oplog_file"
  ```

* Send giganto export file to Giganto server:

  ```toml
  [common]
  cert = "tests/cert.pem"
  key = "tests/key.pem"
  root = "tests/root.pem"
  giganto_ingest_srv_addr = "127.0.0.1:38370"
  giganto_name = "aicers"
  kind ="http"                               # kind in `Network Events` at the bottom
  input = "/path/to/giganto_export_file"

  [file]
  export_from_giganto = true
  ```

* Send sysmon csv file to Giganto server:

  ```toml
  [common]
  cert = "tests/cert.pem"
  key = "tests/key.pem"
  root = "tests/root.pem"
  giganto_ingest_srv_addr = "127.0.0.1:38370"
  giganto_name = "aicers"
  kind ="image_load"                         # kind in `Sysmon Events` at the bottom.
  input = "/path/to/sysmon_file"
  ```

* Send sysmon with elastic search to Giganto server:

  ```toml
  [common]
  cert = "tests/cert.pem"
  key = "tests/key.pem"
  root = "tests/root.pem"
  giganto_ingest_srv_addr = "127.0.0.1:38370"
  giganto_name = "aicers"
  input = "elastic"                          # Use a fixed input value.

  [elastic]
  url = "http://127.0.0.1:9200/"
  event_codes = ["1","7","11","17","25","26",]
  indices = [".ds-winlogbeat-8.8.2-2023.11.29-000001"]
  start_time = "2023-08-06T15:00:00.000Z"
  end_time = "2023-09-07T02:00:00.000Z"
  size = 100000
  dump_dir = "tests/dump"
  elastic_auth = "admin:admin"
  ```

## Defined kind type

### Network Events

| Category | Kind |
| --- | --- |
| Protocol | - conn |
|| - http |
|| - rdp |
|| - smtp |
|| - dns |
|| - ntlm |
|| - kerberos |
|| - ssh |
|| - dce_rpc |
|| - ftp |
|| - mqtt |
|| - ldap |
|| - tls |
|| - smb |
|| - nfs |

### Sysmon Events

| Category | Kind | number |
| --- | --- | --- |
| Event name | - process_create | event 1 |
|| - file_create_time | event 2 |
|| - network_connect | event 3 |
|| - process_terminate | event 5 |
|| - image_load | event 7 |
|| - file_create | event 11 |
|| - registry_value_set | event 13 |
|| - registry_key_rename | event 14 |
|| - file_create_stream_hash | event 15 |
|| - pipe_event | event 17 |
|| - dns_query | event 22 |
|| - file_delete | event 23 |
|| - process_tamper | event 25 |
|| - file_delete_detected | event 26 |

### Netflow, Logs

| Category | Kind | Description |
| --- | --- | --- |
| OpLog | - oplog | Operation log of applications |
| Netflow | - netflow5 | Netflow v5 pcap |
|| - netflow9 | Netflow v9 pcap |
| Security log | - wapples_fw_6.0 | PentaSecurity |
|| - mf2_ips_4.0 | SECU-I |
|| - sniper_ips_8.0 | WINS |
|| - aiwaf_waf_4.1 | Monitorapp |
|| - tg_ips_2.7 | Ahnlab |
|| - vforce_ips_4.6 | NexG |
|| - srx_ips_15.1 | Juniper |
|| - sonicwall_fw_6.5 | SonicWALL |
|| - fgt_ips_6.2 | Fortinet |
|| - shadowwall_ips_5.0 | Duruan |
|| - axgate_fw_2.1 | AXGATE |
| OS log | - ubuntu_syslog_20.04 | Ubuntu 20.04 |
| Web log | - nginx_accesslog_1.25.2 | NGINX |

## License

Copyright 2021-2024 ClumL Inc.

Licensed under [Apache License, Version 2.0][apache-license] (the "License");
you may not use this crate except in compliance with the License.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See [LICENSE](LICENSE) for
the specific language governing permissions and limitations under the License.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the [Apache-2.0
license][apache-license], shall be licensed as above, without any additional
terms or conditions.

[apache-license]: http://www.apache.org/licenses/LICENSE-2.0
