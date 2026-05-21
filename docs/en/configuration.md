# Configuration (TOML)

## Key Configuration Summary

| Configuration | Description | Default |
| --- | --- | --- |
| `cert` | Certificate file path | - |
| `key` | Private key file path | - |
| `ca_certs` | List of CA certificate file paths | - |
| `giganto_ingest_srv_addr` | Giganto ingest server IP:port | - |
| `giganto_name` | Giganto server name used for TLS verification | - |
| `kind` | Type of data to process | - |
| `input` | Input source (file/directory/elastic) | - |
| `report` | Enable transfer statistics reporting | `false` |
| `report_dir` | Report directory. Required when `report = true` | - |
| `log_path` | Log file path. Outputs to stdout if omitted | - |

## Detailed Configuration Behavior

### `kind` Behavior

- If the value is empty or contains only whitespace, REproduce terminates with a
  configuration error.
- Supported `kind` values are listed below.

#### Network Events

`conn`, `http`, `rdp`, `smtp`, `dns`, `ntlm`, `kerberos`, `ssh`, `dce_rpc`,
`ftp`, `mqtt`, `ldap`, `tls`, `smb`, `nfs`, `bootp`, `dhcp`, `radius`,
`malformed_dns`, `icmp`

#### Sysmon Events

`process_create`(1), `file_create_time`(2), `network_connect`(3),
`process_terminate`(5), `image_load`(7), `file_create`(11),
`registry_value_set`(13), `registry_key_rename`(14),
`file_create_stream_hash`(15), `pipe_event`(17), `dns_query`(22),
`file_delete`(23), `process_tamper`(25), `file_delete_detected`(26)

#### Netflow / Log Types

- OpLog: `oplog`
- Netflow: `netflow5`, `netflow9`
- Security logs: `wapples_fw_6.0`, `mf2_ips_4.0`, `sniper_ips_8.0`,
  `aiwaf_waf_4.1`, `tg_ips_2.7`, `vforce_ips_4.6`, `srx_ips_15.1`,
  `sonicwall_fw_6.5`, `fgt_ips_6.2`, `shadowwall_ips_5.0`, `axgate_fw_2.1`
- OS logs: `ubuntu_syslog_20.04`
- Web logs: `nginx_accesslog_1.25.2`
- Unstructured logs: any non-empty string

> **Note**
> For unstructured logs, users may define any non-empty value for `kind`. The
> specified `kind` value is used as an identifier during data storage and retrieval.

### `log_path` Behavior

- If omitted, logs are written to stdout.
- If specified, logs are written to the specified file.
- If the log file cannot be opened, REproduce terminates with an error.

### `report` / `report_dir` Behavior

- If `report = true`, transfer statistics are written to `{kind}.report` under
  `report_dir`. The directory is automatically created if it does not exist.
- If `report = true` but `report_dir` is not specified, REproduce terminates
  with a configuration error.
- If `report = false` (default), `report_dir` is ignored.
- Both absolute and relative paths are supported, but absolute paths are
  recommended to avoid ambiguity.

## File Mode Configuration

Used to configure processing ranges, polling mode, and Giganto export file
import behavior for single-file input.

| Configuration | Description | Default |
| --- | --- | --- |
| `import_from_giganto` | Enable Giganto export file processing | `false` |
| `polling_mode` | Enable file polling mode | `false` |
| `transfer_count` | Number of records to transfer | - |
| `transfer_skip_count` | Number of records to skip before transfer | - |
| `last_transfer_line_suffix` | Suffix for last transferred line file | - |

## Directory Mode Configuration

Used to filter files in a directory or continuously monitor newly added files.

| Configuration | Description | Default |
| --- | --- | --- |
| `file_prefix` | Target filename prefix for directory input | - |
| `polling_mode` | Enable directory polling mode | `false` |

## Elastic Mode Configuration

Used when retrieving logs from an Elasticsearch server. All fields are required
when `input = "elastic"`.

| Configuration | Description |
| --- | --- |
| `url` | Elasticsearch server IP:port |
| `event_codes` | Target Sysmon event code list |
| `indices` | Elasticsearch index list to query |
| `start_time` | Start time of target events |
| `end_time` | End time of target events |
| `size` | Maximum number of records per query |
| `dump_dir` | Directory path for storing CSV files |
| `elastic_auth` | Elasticsearch authentication (`username:password`) |

## Configuration Examples

### Example configuration for sending a Zeek log file to Giganto

```toml
cert = "/opt/clumit/keys/reproduce_cert.pem"
key = "/opt/clumit/keys/reproduce_key.pem"
ca_certs = ["/opt/clumit/keys/manager_cert.pem"]
giganto_ingest_srv_addr = "127.0.0.1:38370"
giganto_name = "data-store"
kind = "dns"
input = "/path/to/zeek_file"
```

### Example configuration for importing Sysmon data from Elasticsearch

```toml
cert = "/opt/clumit/keys/reproduce_cert.pem"
key = "/opt/clumit/keys/reproduce_key.pem"
ca_certs = ["/opt/clumit/keys/manager_cert.pem"]
giganto_ingest_srv_addr = "127.0.0.1:38370"
giganto_name = "data-store"
kind = "process_create"
input = "elastic"

[elastic]
url = "http://127.0.0.1:9200/"
event_codes = ["1", "7", "11", "17", "25", "26"]
indices = [".ds-winlogbeat-8.8.2-2023.11.29-000001"]
start_time = "2023-08-06T15:00:00.000Z"
end_time = "2023-09-07T02:00:00.000Z"
size = 100000
dump_dir = "/path/to/dump"
elastic_auth = "admin:admin"
```

### Example configuration for enabling reports

```toml
report = true
report_dir = "/var/lib/reproduce/reports"
```

### Example file polling configuration

```toml
[file]
polling_mode = true
```

### Example directory file prefix filtering

```toml
[directory]
file_prefix = "dns"
polling_mode = true
```
