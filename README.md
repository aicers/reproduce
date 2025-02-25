# REproduce

REproduce monitors a log file or a directory of log files, and sends appended
entries to a Giganto server.

[![Coverage Status](https://codecov.io/gh/aicers/reproduce/branch/main/graph/badge.svg)](https://codecov.io/gh/aicers/reproduce)

## Requirements

- Giganto 0.23.0 or higher.

## Usage

To start REproduce, provide a path to the TOML configuration file:

```sh
reproduce <CONFIG_PATH>
```

- `<CONFIG_PATH>`: Path to the TOML configuration file.

To support pcap parser for netflow v9, templates would be read from
the environment variable `NETFLOW_TEMPLATES_PATH`.

## Configuration

- Below is a detailed breakdown of all available configuration fields.

### [Common]

- This section is required and must be configured properly for REproduce to
  function.

<!-- markdownlint-disable -->

| Field                     | Description                                                                | Required | Default    |
| ------------------------- | -------------------------------------------------------------------------- | -------- | ---------- |
| `cert`                    | Path to the private key file                                               | Yes      | -          |
| `key`                     | Path to the certificate file                                               | Yes      | -          |
| `ca_certs`                | List of paths to CA certificate files                                      | Yes      | -          |
| `giganto_ingest_srv_addr` | IP address and port of the Giganto ingest server                           | Yes      | -          |
| `giganto_name`            | Name of Giganto server                                                     | Yes      | -          |
| `kind`                    | Type of data being processed (See [Defined kind type](#defined-kind-type)) | No       | "" (empty) |
| `input`                   | Specifies the input source: file, directory, or elastic                    | Yes      | -          |
| `report`                  | Enables or disables reporting of transfer statistics                       | No       | false      |
| `log_dir`                 | Directory for log files. If not specified, logs are sent to stdout.        | No       | -          |

<!-- markdownlint-enable -->

### [File]

- This section is required only if you are using file-based input.

<!-- markdownlint-disable -->

| Field                       | Description                                                | Required | Default |
| --------------------------- | ---------------------------------------------------------- | -------- | ------- |
| `export_from_giganto`       | Enables processing of files exported from Giganto          | No       | false   |
| `polling_mode`              | Enables or disables file polling mode                      | No       | false   |
| `transfer_count`            | Number of lines or packets to send                         | No       | -       |
| `transfer_skip_count`       | Number of lines or packets to skip before sending          | No       | -       |
| `last_transfer_line_suffix` | Suffix used for the file storing the last transferred line | No       | -       |

<!-- markdownlint-enable -->

### [Directory]

- This section is required only if you are processing log files from a
  directory.

<!-- markdownlint-disable -->

| Field          | Description                                     | Required | Default |
| -------------- | ----------------------------------------------- | -------- | ------- |
| `file_prefix`  | Prefix for filenames when using directory input | No       | -       |
| `polling_mode` | Enables or disables directory polling mode      | No       | false   |

<!-- markdownlint-enable -->

### [Elastic]

- This section is required only if you are fetching logs from an Elasticsearch
  server.

<!-- markdownlint-disable -->

| Field          | Description                                                  | Required | Default |
| -------------- | ------------------------------------------------------------ | -------- | ------- |
| `url`          | IP address and port of the Elasticsearch server              | Yes      | -       |
| `event_codes`  | List of target event codes                                   | Yes      | -       |
| `indices`      | List of Elasticsearch indices to query                       | Yes      | -       |
| `start_time`   | The start time of target events                              | Yes      | -       |
| `end_time`     | The end time of target events                                | Yes      | -       |
| `size`         | Maximum number of records to fetch per query                 | Yes      | -       |
| `dump_dir`     | Path to the directory where CSV files are saved              | Yes      | -       |
| `elastic_auth` | Elasticsearch authentication credentials (username:password) | Yes      | -       |

<!-- markdownlint-enable -->

## Examples

### Convert a Zeek log file and send it to a Giganto server

- Sends a Zeek log file to the Giganto server, setting `kind` to `dns`.

  ```toml
  [common]
  cert = "/CA/cert.pem"
  key = "/CA/key.pem"
  ca_certs = ["/CA/ca_cert.pem"]
  giganto_ingest_srv_addr = "127.0.0.1:38370"
  giganto_name = "aicers"
  kind = "dns"                                # Data kind (see `Network Events` section).
  input = "/path/to/zeek_file"
  ```

### Send an operation log to a Giganto server

- Sends an operation log file to the Giganto server using the fixed data kind
  oplog.

  ```toml
  [common]
  cert = "/CA/cert.pem"
  key = "/CA/key.pem"
  ca_certs = ["/CA/ca_cert.pem"]
  giganto_ingest_srv_addr = "127.0.0.1:38370"
  giganto_name = "aicers"
  kind = "oplog"                              # Fixed data kind.
  input = "/path/to/oplog_file"
  ```

### Send a Giganto export file to a Giganto server

- Sends a previously exported Giganto file to the Giganto server.

  ```toml
  [common]
  cert = "/CA/cert.pem"
  key = "/CA/key.pem"
  ca_certs = ["/CA/ca_cert.pem"]
  giganto_ingest_srv_addr = "127.0.0.1:38370"
  giganto_name = "aicers"
  kind = "http"                               # Data kind (see `Network Events` section).
  input = "/path/to/giganto_export_file"

  [file]
  export_from_giganto = true
  ```

### Send a Sysmon CSV file to a Giganto server

- Sends a Sysmon log file (CSV format) to the Giganto server, specifying the
  data kind as image_load.

  ```toml
  [common]
  cert = "/CA/cert.pem"
  key = "/CA/key.pem"
  ca_certs = ["/CA/ca_cert.pem"]
  giganto_ingest_srv_addr = "127.0.0.1:38370"
  giganto_name = "aicers"
  kind = "image_load"                         # Data kind (see `Sysmon Events` section).
  input = "/path/to/sysmon_file"
  ```

### Send Sysmon data from Elasticsearch to a Giganto server

- Queries Sysmon event logs from an Elasticsearch server and sends them to the
  Giganto server.

  ```toml
  [common]
  cert = "/CA/cert.pem"
  key = "/CA/key.pem"
  ca_certs = ["/CA/ca_cert.pem"]
  giganto_ingest_srv_addr = "127.0.0.1:38370"
  giganto_name = "aicers"
  input = "elastic"                          # Fixed input type.

  [elastic]
  url = "http://127.0.0.1:9200/"
  event_codes = ["1","7","11","17","25","26",]
  indices = [".ds-winlogbeat-8.8.2-2023.11.29-000001"]
  start_time = "2023-08-06T15:00:00.000Z"
  end_time = "2023-09-07T02:00:00.000Z"
  size = 100000
  dump_dir = "/path/to/dump"
  elastic_auth = "admin:admin"
  ```

## Defined kind type

- Below is a list of supported `kind` values for different event categories.

### Network Events

| Category | Kind     |
| -------- | -------- |
| Protocol | conn     |
|          | http     |
|          | rdp      |
|          | smtp     |
|          | dns      |
|          | ntlm     |
|          | kerberos |
|          | ssh      |
|          | dce_rpc  |
|          | ftp      |
|          | mqtt     |
|          | ldap     |
|          | tls      |
|          | smb      |
|          | nfs      |
|          | bootp    |
|          | dhcp     |

### Sysmon Events

| Category   | Kind                    | Number   |
| ---------- | ----------------------- | -------- |
| Event name | process_create          | event 1  |
|            | file_create_time        | event 2  |
|            | network_connect         | event 3  |
|            | process_terminate       | event 5  |
|            | image_load              | event 7  |
|            | file_create             | event 11 |
|            | registry_value_set      | event 13 |
|            | registry_key_rename     | event 14 |
|            | file_create_stream_hash | event 15 |
|            | pipe_event              | event 17 |
|            | dns_query               | event 22 |
|            | file_delete             | event 23 |
|            | process_tamper          | event 25 |
|            | file_delete_detected    | event 26 |

### Netflow, Logs

| Category     | Kind                   | Description                   |
| ------------ | ---------------------- | ----------------------------- |
| OpLog        | oplog                  | Operation log of applications |
| Netflow      | netflow5               | Netflow v5 pcap               |
|              | netflow9               | Netflow v9 pcap               |
| Security log | wapples_fw_6.0         | PentaSecurity                 |
|              | mf2_ips_4.0            | SECU-I                        |
|              | sniper_ips_8.0         | WINS                          |
|              | aiwaf_waf_4.1          | Monitorapp                    |
|              | tg_ips_2.7             | Ahnlab                        |
|              | vforce_ips_4.6         | NexG                          |
|              | srx_ips_15.1           | Juniper                       |
|              | sonicwall_fw_6.5       | SonicWALL                     |
|              | fgt_ips_6.2            | Fortinet                      |
|              | shadowwall_ips_5.0     | Duruan                        |
|              | axgate_fw_2.1          | AXGATE                        |
| OS log       | ubuntu_syslog_20.04    | Ubuntu 20.04                  |
| Web log      | nginx_accesslog_1.25.2 | NGINX                         |

## License

Copyright 2021-2025 ClumL Inc.

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
