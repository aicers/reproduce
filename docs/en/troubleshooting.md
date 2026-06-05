# Troubleshooting

Use this page by matching the visible symptom first, then checking the related
configuration fields and log messages.

## Process Exits Before Startup

Check the command line first.

- Run REproduce with exactly one configuration path:
  `reproduce /path/to/config.toml`.
- Do not pass extra positional arguments.
- Use `reproduce --help` to confirm the expected command format.

If the command is correct, check whether the configuration file can be read.

## Configuration File Error

Check that all required top-level fields are present:

- `cert`
- `key`
- `ca_certs`
- `giganto_ingest_srv_addr`
- `giganto_name`
- `kind`
- `input`

Also check:

- `kind` must not be empty or only whitespace.
- `giganto_ingest_srv_addr` must be `IP:PORT`, for example
  `127.0.0.1:38370` or `[::1]:38370`.
- Hostnames such as `localhost:38370` are not accepted for
  `giganto_ingest_srv_addr`.
- If `report = true`, `report_dir` must be configured.
- If `input = "elastic"`, all fields in `[elastic]` must be configured.

See [Top-Level Settings](configuration.md#top-level-settings) for the required
fields.

## Log File Cannot Be Opened

If `log_path` is configured, REproduce must be able to create or append to that
file.

- Confirm that the parent directory exists.
- Confirm that the REproduce process has write permission.
- Use an absolute path for service or scheduled runs.
- Temporarily remove `log_path` to write logs to stdout while diagnosing the
  issue.

## Cannot Connect to the Data Store

Check these items:

- `giganto_ingest_srv_addr` has the correct IP address and port.
- The data store server is reachable from the REproduce host.
- The data store server version is 0.27.0 or later.
- `giganto_name` matches the server name expected by TLS verification.
- `cert` and `key` are a matching client certificate and private key.
- `ca_certs` contains the CA certificates required to validate the data store
  server.

If certificates were rotated while REproduce is running, send `SIGHUP` on Unix
systems so the updated files can be used on the next reconnect.

## Input Path Uses the Wrong Mode

REproduce selects the input mode from `input`.

- `input = "elastic"` selects Elastic mode.
- An existing directory path selects directory mode.
- Any other value selects file mode.

If you intended to use directory mode but the directory does not exist at
startup, REproduce treats the value as a file path. Create the directory or fix
the path before starting REproduce.

## Input Data Is Not Processed

Check the input and filtering settings:

- Confirm that the input file or directory exists and is readable.
- In directory mode, confirm that `file_prefix` is not filtering out the target
  files.
- If newly appended data should be processed, enable `[file].polling_mode`.
- If new files should be processed from a directory, enable
  `[directory].polling_mode`.
- If `transfer_count` is set, confirm that the configured limit is not stopping
  earlier than expected.
- If `transfer_skip_count` is set, confirm that it is not skipping all available
  records or packets.

## Checkpoint Resumes From an Unexpected Position

Check `[file].last_transfer_line_suffix` and the generated checkpoint file.

- The checkpoint filename is `{input}_{last_transfer_line_suffix}`.
- In directory mode, each source file has its own checkpoint file.
- `transfer_skip_count` takes priority over the checkpoint value for that run.
- If the checkpoint file is missing, unreadable, not UTF-8, or not a number,
  REproduce starts from position `0` and logs a warning.
- Files ending with `_{last_transfer_line_suffix}` are skipped in directory mode
  so checkpoint files are not processed as input.

If real input filenames already end with the checkpoint suffix, choose a
different suffix.

## Data Store Export Input Fails

When processing a data store export file, set:

```toml
[file]
import_from_giganto = true
```

Some network `kind` values are accepted only for data store export input:

`mqtt`, `smb`, `nfs`, `bootp`, `dhcp`, `radius`, `malformed_dns`, `icmp`

If one of these kinds is used without `import_from_giganto = true`, REproduce
exits with an unsupported input error.

## Operation Log Input Fails

For `kind = "oplog"`, the input filename must identify the source service before
the first dot. For example, `manager.log` uses `manager` as the service name.

If the filename does not follow the expected service log naming convention,
REproduce exits with an invalid service name error.

## Netflow v9 Data Is Not Parsed

Check Netflow-specific prerequisites:

- Confirm that the `netflow` build feature is enabled. It is enabled by default.
- If the pcap does not contain the required templates, set
  `NETFLOW_TEMPLATES_PATH` to the directory containing saved templates.
- Confirm that the configured path is readable by the REproduce process.

```bash
export NETFLOW_TEMPLATES_PATH=/path/to/netflow_templates
```

## Elastic Mode Cannot Retrieve Data

Check the `[elastic]` configuration:

- `url` points to the correct Elasticsearch server.
- `elastic_auth` is in `username:password` format.
- `indices` contains the target indices.
- `event_codes` contains supported Sysmon event codes.
- `start_time` and `end_time` cover the expected event time range.
- `size` is large enough for the expected result set.
- `dump_dir` exists or can be created, and is writable.

If no matching data is retrieved, REproduce exits with a no-data error.

## Report File Is Missing

Check report settings:

- `report` must be set to `true`.
- `report_dir` must be configured when `report = true`.
- The process must have permission to create the directory and append to the
  `{kind}.report` file.
- Relative `report_dir` values are resolved from the process working directory.

Use an absolute `report_dir` for service or scheduled runs.
