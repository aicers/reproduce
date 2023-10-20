# REproduce

REproduce monitors a log file or a directory of log files, and sends appended
entries to a Giganto server.

[![Coverage Status](https://codecov.io/gh/aicers/reproduce/branch/main/graph/badge.svg?token=2P7VSZ1KFV)](https://codecov.io/gh/aicers/reproduce)

## Requirements

* Giganto 0.13.0.

## Build

REproduce may be built as a single binary for portability. Make sure that the
musl target is available. The following command installs the Rust compiler for
`x86_64-unknown-linux-musl` if it is not already installed:

```sh
rustup target add x86_64-unknown-linux-musl
```

Then the portable REproduce binary, `reproduce`, can be created with the
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

* Convert a zeek log file and send it to Giganto server from specific line:

  ```sh
  reproduce -i LOG_20220921 -o giganto -G 127.0.0.1:38370 -N server_name \
      -C config.toml -k protocol -f 10
  ```

* Send operation log to Giganto server:

  ```sh
  reproduce -i AGENT_NAME.log -o giganto -G 127.0.0.1:38370 -N server_name \
    -C config.toml -k oplog
  ```

* Send giganto export file to Giganto server:

  ```sh
  reproduce -i LOG_20230209 -o giganto -G 127.0.0.1:38370 -N server_name \
    -C config.toml -k protocol -m
  ```

* Send sysmon csv file to Giganto server:

  ```sh
  reproduce -i EVENT_LOG.csv -o giganto -G 127.0.0.1:38370 -N server_name \
    -C config.toml -k event_name
  ```

## Defined kind type

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

| Category | Kind | Description |
| --- | --- | --- |
| Oplog | - oplog | Operation log of applications |
| Netflow | - netflow5 | Netflow v5 pcap |
|| - netflow9 | Netflow v9 pcap |

## License

Copyright 2021-2023 EINSIS, Inc.

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
