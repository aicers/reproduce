# REproduce

REproduce monitors a log file or a directory of log files, and sends appended
entries to a Kafka server. Each message to Kafka is assigned an event ID
consisting of system time in seconds (32 bits), sequence number (24 bits), and
data source ID (8 bits).

[![Coverage Status](https://codecov.io/gh/petabi/reproduce/branch/main/graph/badge.svg?token=2P7VSZ1KFV)](https://codecov.io/gh/petabi/reproduce)

## Usage

The following command shows its usage:

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

## Building a Docker Image

Run the following command in a directory that has a Dockerfile:

```
docker build -t reproduce .
```

## Running with Docker

Run with the following command

```sh
docker run --mount type=bind,source=[the directory containing the target],target=/data \
           --mount type=bind,source=[report or log directory],target=/report reproduce:latest -i [the target file] -b localhost:9092 -t topic
```

## License

Copyright 2018-2021 Petabi, Inc.

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
