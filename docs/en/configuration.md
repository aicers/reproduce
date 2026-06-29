# Configuration (TOML)

REproduce is configured with one TOML file. The file contains required
top-level settings and optional sections for file, directory, and Elastic mode
behavior.

## Top-Level Settings

Fields marked with `(*)` are required. Fields marked with `(†)` are required
only under the condition described below the table.

| Configuration | Description | Default |
| --- | --- | --- |
| `cert` (*) | Client certificate file path | - |
| `key` (*) | Private key file path for the client certificate | - |
| `ca_certs` (*) | Trusted CA certificate file paths | - |
| `giganto_ingest_srv_addr` (*) | Data store ingest `IP:PORT` | - |
| `giganto_name` (*) | Data store server name for TLS verification | - |
| `kind` (*) | Type of data to process | - |
| `input` (*) | Input source | - |
| `report` | Enable transfer statistics reporting | `false` |
| `report_dir` (†) | Directory for transfer statistics reports | - |
| `log_path` | Log file path | - |

`(†)` Required when `report = true`.

The `kind` value must not be empty or contain only whitespace.

The `giganto_ingest_srv_addr` value must be an `IP:PORT` socket address, such as
`127.0.0.1:38370` or `[::1]:38370`. Hostnames are not accepted.

Each file listed in `ca_certs` may contain one or more PEM-encoded
certificates, such as a CA bundle or a full-chain file.

## Input Mode Selection

REproduce chooses the input mode from `input`.

| `input` value | Selected mode |
| --- | --- |
| `"elastic"` | Elastic mode |
| Existing directory path | Directory mode |
| Any other path | File mode |

If you intend to use directory mode, confirm that the directory exists before
starting REproduce. A missing directory path is treated as a file path.

## `kind` Values

### Network Events

The following `kind` values can be used for directly parsed Zeek-style network
logs:

`conn`, `http`, `rdp`, `smtp`, `dns`, `ntlm`, `kerberos`, `ssh`, `dce_rpc`,
`ftp`, `ldap`, `tls`

The following network `kind` values are accepted only when processing data store
export files with `import_from_giganto = true`:

`mqtt`, `smb`, `nfs`, `bootp`, `dhcp`, `radius`, `malformed_dns`, `icmp`

### Sysmon Events

| Event code | `kind` |
| --- | --- |
| 1 | `process_create` |
| 2 | `file_create_time` |
| 3 | `network_connect` |
| 5 | `process_terminate` |
| 7 | `image_load` |
| 11 | `file_create` |
| 13 | `registry_value_set` |
| 14 | `registry_key_rename` |
| 15 | `file_create_stream_hash` |
| 17 | `pipe_event` |
| 22 | `dns_query` |
| 23 | `file_delete` |
| 25 | `process_tamper` |
| 26 | `file_delete_detected` |

### Other Supported Inputs

- Operation logs: `oplog`
- Netflow: `netflow5`, `netflow9`
- Security logs: `wapples_fw_6.0`, `mf2_ips_4.0`, `sniper_ips_8.0`,
  `aiwaf_waf_4.1`, `tg_ips_2.7`, `vforce_ips_4.6`, `srx_ips_15.1`,
  `sonicwall_fw_6.5`, `fgt_ips_6.2`, `shadowwall_ips_5.0`, `axgate_fw_2.1`
- OS logs: `ubuntu_syslog_20.04`
- Web logs: `nginx_accesslog_1.25.2`

Any other non-empty `kind` value is handled as an unstructured log kind. The
chosen value is used as the event identifier in the data store.

## Logging

If `log_path` is omitted, logs are written to stdout. If `log_path` is set, logs
are appended to the specified file. Startup fails if the file cannot be opened.

The default log level is `INFO` when `RUST_LOG` is not set. Set `RUST_LOG`
before running REproduce to adjust log verbosity.

```bash
RUST_LOG=debug reproduce /path/to/config.toml
```

## Reports

When `report = true`, REproduce appends transfer statistics to
`{kind}.report` inside `report_dir`. The report directory is created
automatically if it does not exist.

- `report_dir` must be set when `report = true`.
- `report_dir` is ignored when `report = false`.
- Relative paths are resolved from the process working directory.
- Absolute paths are recommended for service or scheduled runs.

```toml
report = true
report_dir = "/var/lib/reproduce/reports"
```

## File Mode Configuration

Use the `[file]` section when you need to change per-file behavior. Most
settings also apply to each file processed in directory mode. `polling_mode`
applies only to supported single-file log input.

All fields in `[file]` are optional.

| Configuration | Description | Default |
| --- | --- | --- |
| `import_from_giganto` | Process a data store export file | `false` |
| `polling_mode` | Keep watching a single file for appended data | `false` |
| `transfer_count` | Transfer limit. `0` or omitted means no limit | - |
| `transfer_skip_count` | Records or packets to skip before transfer | - |
| `last_transfer_line_suffix` | Suffix used for checkpoint files | - |

`export_from_giganto` is a deprecated name for `import_from_giganto`. Use
`import_from_giganto` in new configurations.

### Checkpoint Behavior

When `last_transfer_line_suffix` is set, REproduce saves the latest committed
position in a checkpoint file named:

```text
{input}_{last_transfer_line_suffix}
```

For example, if `input = "/data/conn.log"` and
`last_transfer_line_suffix = "offset"`, the checkpoint file is
`/data/conn.log_offset`.

On the next run, REproduce resumes from the checkpoint when
`transfer_skip_count` is not set. If `transfer_skip_count` is set, it takes
priority over the checkpoint value.

When REproduce skips a record or packet because it cannot parse it, the
checkpoint still advances past that input. Review the checkpoint before
retrying corrected input, because REproduce may otherwise start after it.

In directory mode, each source file gets its own checkpoint file. Files whose
basename ends with `_{last_transfer_line_suffix}` are skipped during directory
scans so checkpoint files are not processed as input.

Choose a suffix that does not collide with real input filenames.

## Directory Mode Configuration

Use the `[directory]` section when `input` is an existing directory and you need
filename filtering or directory polling.

All fields in `[directory]` are optional.

| Configuration | Description | Default |
| --- | --- | --- |
| `file_prefix` | Process files with this basename prefix | - |
| `polling_mode` | Keep scanning the directory for files to process | `false` |

Directory mode recursively processes regular files below the configured
directory, including files reached through symbolic links. If `file_prefix` is
set, files whose basenames do not start with that prefix are ignored.

When `polling_mode = true`, REproduce keeps scanning for new matching files. If
`polling_mode = false`, REproduce processes the files found during the run and
then finishes.

In directory mode, use `[directory].polling_mode` for polling. If
`[file].polling_mode = true` is also set, REproduce ignores it and logs a
warning.

## Elastic Mode Configuration

Use Elastic mode by setting `input = "elastic"` and adding an `[elastic]`
section.

All fields in `[elastic]` are required.

| Configuration | Description |
| --- | --- |
| `url` | Elasticsearch server URL |
| `event_codes` | Target Sysmon event code list |
| `indices` | Elasticsearch index list to query |
| `start_time` | Start time of target events |
| `end_time` | End time of target events |
| `size` | Maximum number of records per query |
| `dump_dir` | Directory for temporary retrieved CSV files |
| `elastic_auth` | Elasticsearch `username:password` auth |

The top-level `kind` field must still contain a non-empty value. In Elastic
mode, `event_codes` determines which Sysmon event types are retrieved from
Elasticsearch and transferred. If reporting is enabled, `kind` is used in the
report filename.

## Configuration Examples

### Send a Zeek DNS Log File

```toml
cert = "/opt/clumit/keys/reproduce_cert.pem"
key = "/opt/clumit/keys/reproduce_key.pem"
ca_certs = ["/opt/clumit/keys/manager_cert.pem"]
giganto_ingest_srv_addr = "127.0.0.1:38370"
giganto_name = "data-store"
kind = "dns"
input = "/data/zeek/dns.log"
```

### Send Files from a Directory

```toml
cert = "/opt/clumit/keys/reproduce_cert.pem"
key = "/opt/clumit/keys/reproduce_key.pem"
ca_certs = ["/opt/clumit/keys/manager_cert.pem"]
giganto_ingest_srv_addr = "127.0.0.1:38370"
giganto_name = "data-store"
kind = "dns"
input = "/data/zeek"

[directory]
file_prefix = "dns"
polling_mode = true
```

### Resume a File Transfer with Checkpoints

```toml
cert = "/opt/clumit/keys/reproduce_cert.pem"
key = "/opt/clumit/keys/reproduce_key.pem"
ca_certs = ["/opt/clumit/keys/manager_cert.pem"]
giganto_ingest_srv_addr = "127.0.0.1:38370"
giganto_name = "data-store"
kind = "dns"
input = "/data/zeek/dns.log"

[file]
last_transfer_line_suffix = "offset"
polling_mode = true
```

### Import a Data Store Export File

```toml
cert = "/opt/clumit/keys/reproduce_cert.pem"
key = "/opt/clumit/keys/reproduce_key.pem"
ca_certs = ["/opt/clumit/keys/manager_cert.pem"]
giganto_ingest_srv_addr = "127.0.0.1:38370"
giganto_name = "data-store"
kind = "http"
input = "/data/exports/http.log"

[file]
import_from_giganto = true
```

### Import Sysmon Data from Elasticsearch

```toml
cert = "/opt/clumit/keys/reproduce_cert.pem"
key = "/opt/clumit/keys/reproduce_key.pem"
ca_certs = ["/opt/clumit/keys/manager_cert.pem"]
giganto_ingest_srv_addr = "127.0.0.1:38370"
giganto_name = "data-store"
kind = "elastic_sysmon"
input = "elastic"

[elastic]
url = "http://127.0.0.1:9200/"
event_codes = ["1", "7", "11", "17", "25", "26"]
indices = [".ds-winlogbeat-8.8.2-2023.11.29-000001"]
start_time = "2023-08-06T15:00:00.000Z"
end_time = "2023-09-07T02:00:00.000Z"
size = 100000
dump_dir = "/var/lib/reproduce/elastic-dump"
elastic_auth = "admin:admin"
```
