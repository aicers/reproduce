# Operations

## Start Command

Run REproduce with exactly one TOML configuration file path.

```bash
reproduce <CONFIG_PATH>
```

| Argument or flag | Behavior |
| --- | --- |
| `<CONFIG_PATH>` | Starts REproduce with the TOML configuration file |
| `-h`, `--help` | Prints help and exits |
| `-V`, `--version` | Prints version information and exits |

If no configuration path is provided, or if more than one positional argument is
provided, REproduce prints an error and exits with status code `1`.

## Runtime Lifecycle

REproduce starts by loading the configuration, initializing logging, installing
signal handlers, and logging `Data Broker started`.

Runtime behavior then depends on the configured input source:

- Single input file:
  Processes the file once. If file polling is enabled, keeps waiting for
  appended data.
- Existing directory:
  Processes matching files in sorted order. If directory polling is enabled,
  rescans for new matching files every 10 seconds.
- Elasticsearch:
  Retrieves Sysmon event data, writes temporary CSV files under `dump_dir`,
  and transfers them. After all files transfer successfully, REproduce removes
  the temporary files and directory, then exits.
  The process needs permission to manage those temporary files.
  If processing does not complete, temporary files can remain under `dump_dir`.

When a run finishes successfully, REproduce logs `Data Broker completed`.

When a fatal runtime error occurs, REproduce logs `Terminated with error: ...`
and exits with status code `1`.

## Data Store Connection

REproduce connects to the data store ingest server before sending events.

Useful connection-related log lines include:

- `Connected to data store ingest server at ...`
- `Server timeout, reconnecting...`
- `Data Store ended`

If the data store connection times out during startup or reconnect, REproduce
keeps retrying at 5-second intervals unless the process is shutting down.

## Polling Behavior

File polling and directory polling keep the process running after the currently
available input has been processed.

- File polling waits for newly appended data in the same input file.
- Directory polling rescans the configured directory every 10 seconds.
- Directory polling does not reprocess files already handled in the same run.
- If directory polling is disabled and no input file is found, REproduce logs
  `No input file` and completes the run.

See [Configuration](configuration.md) for the polling fields.

## Logs

By default, logs are written to stdout at `INFO` level. Set `log_path` to append
logs to a file instead.

Set `RUST_LOG` to adjust verbosity:

```bash
RUST_LOG=debug reproduce /path/to/config.toml
```

Useful startup and progress log lines include:

- `Initialized tracing logger`
- `Data Broker started`
- `File: ...` (directory and Elastic modes only)
- `Data Broker completed`
- `Terminated with error: ...`

In directory and Elastic modes, `File: ...` identifies each file when
REproduce starts processing it. Single-file mode does not emit this log line.

## Reports

When reporting is enabled, REproduce appends transfer statistics to the report
file after each input processing run.

If report writing fails after processing, REproduce logs `Cannot write report:
...`. The transfer itself is not treated as failed solely because the report
could not be written.

See [Configuration](configuration.md#reports) for report settings.

## Reload and Shutdown

On Unix systems:

- `SIGHUP` marks TLS material for reload. It does not force an immediate data
  store reconnect. The process keeps running.
- `SIGINT` and `SIGTERM` request graceful shutdown.

On non-Unix systems, `Ctrl-C` requests graceful shutdown.

Use `SIGHUP` after replacing certificate, private key, or CA certificate files
on disk. The new files are used when a reconnect happens later. If the reload
attempt cannot establish a working connection, REproduce keeps the last working
connection settings and retries the reload on a later reconnect.

## After Startup

Verify the following after running REproduce:

- Logs show `Data Broker started`.
- Logs show a successful data store connection.
- In directory and Elastic modes, input files appear in `File: ...` log lines
  when processing begins.
- Long-running polling behavior matches the configured polling settings.
- Reports are written under `report_dir` when reporting is enabled.
