# Troubleshooting

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

## TLS Files Cannot Be Loaded

If REproduce cannot read or validate TLS files, the run ends during data store
connection setup.

Check the following when logs report that a certificate or key file cannot be
read, contains no certificate or private key, or has invalid PEM data:

- Each configured path identifies an existing file readable by the REproduce
  process.
- `cert` contains a client certificate and `key` contains its private key.
- The client certificate and private key form a matching pair.
- Each file listed in `ca_certs` contains at least one PEM-encoded
  certificate.

## Cannot Connect to the Data Store

Check these items:

- `giganto_ingest_srv_addr` has the correct IP address and port.
- The data store server is reachable from the REproduce host.
- REproduce and the data store server are from a compatible package set.
- `giganto_name` matches the server name expected by TLS verification.
- `ca_certs` contains the CA certificates required to validate the data store
  server.

If certificates were rotated while REproduce is running, send `SIGHUP` on Unix
systems so the updated files can be used on the next reconnect.

## Directory Input Is Processed as a File

Directory mode requires `input` to refer to an existing directory when
REproduce starts. Otherwise, REproduce processes the value as a single file
path.

Confirm that the configured directory exists and that the REproduce process can
access it.

## Input Data Is Not Processed

Check the input and filtering settings:

- Confirm that the input file or directory exists and is readable.
- In directory mode, confirm that `file_prefix` is not filtering out the target
  files.
- If `transfer_count` is set, confirm that the configured limit is not stopping
  earlier than expected.
- If `transfer_skip_count` is set, confirm that it is not skipping all available
  records or packets.

## Newly Added Input Is Not Processed

Use this section when REproduce processed the available input but does not pick
up later changes.

- To process data appended to supported single-file log input, enable
  `[file].polling_mode`.
- To process files added to a directory, enable `[directory].polling_mode`.
- In directory mode, `[file].polling_mode` is ignored. Use
  `[directory].polling_mode` to check for newly added matching files.

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

## Data Store Export Input Is Not Processed

If logs contain `Failed to convert data #...` or `Invalid record: ...`, check
the following:

- `kind` matches the records in the input file.
- The file was exported by a data store server from a compatible package set.
- `import_from_giganto` is set to `true`.

## Operation Log Input Fails

For `kind = "oplog"`, the input filename must identify the source service before
the first dot. For example, `manager.log` uses `manager` as the service name.

If the filename does not follow the expected service log naming convention,
REproduce exits with an invalid service name error.

## Netflow v9 Data Is Not Parsed

Check Netflow-specific prerequisites:

- Confirm that the `netflow` build feature is enabled. It is enabled by default.
- If the pcap does not contain the required templates, set
  `NETFLOW_TEMPLATES_PATH` to a template cache file that REproduce can read and
  write.
