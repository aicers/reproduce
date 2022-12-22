# REproduce

REproduce monitors a log file or a directory of log files, and sends appended
entries to a Kafka server. Each message to Kafka is assigned an event ID
consisting of system time in seconds (32 bits), sequence number (24 bits), and
data source ID (8 bits).

[![Coverage Status](https://codecov.io/gh/aicers/reproduce/branch/main/graph/badge.svg?token=2P7VSZ1KFV)](https://codecov.io/gh/aicers/reproduce)

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

## Examples

* Convert a log file and send it to the kafka server:

    ```sh
    reproduce -i LOG_20180906 -b 192.168.10.1:9092 -t sample_topic
    ```

* Send all log files whose names starting with `msg` in the `/data/LOG`
  directory recursively:

    ```sh
    reproduce -i /data/LOG -n msg -b 192.168.4.5:9092 -t syslog -e
    ```

* Send all log files in the `/data/LOG` directory recursively. The directory
  will be polled periodically (every 3 seconds by default). A new file will be
  sent as well.

    ```sh
    reproduce -i /data/LOG -v -b 192.168.4.5:9092 -t syslog -e
    ```

* Convert a log file and send it to Giganto server:

    ```sh
    reproduce -i LOG_20220921 -o giganto -G 127.0.0.1:38370 -N server_name \
        -C config.toml -k test_kind
    ```

* Send Operation log to Giganto server:

    ```sh
    reproduce -i AGENT_NAME.log -o giganto -G 127.0.0.1:38370 -N server_name \
      -C config.toml -k oplog

## License

Copyright 2021-2022 EINSIS, Inc.

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
