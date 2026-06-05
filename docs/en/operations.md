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

## Before Starting

Check the following before running the command:

- The configuration file exists and is readable.
- Prerequisites for certificates, input access, and optional input sources are
  complete.
- Required configuration fields are present.
- The configured input mode matches the intended source.

See [Prerequisites](prerequisites.md) for preparation requirements and
[Configuration](configuration.md) for TOML fields.

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
  transfers them, removes the temporary files and directory, then exits.

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
- `File: ...`
- `Data Broker completed`
- `Terminated with error: ...`

## Reports

When reporting is enabled, REproduce appends transfer statistics to the report
file after each input processing run.

If report writing fails after processing, REproduce logs `Cannot write report:
...`. The transfer itself is not treated as failed solely because the report
could not be written.

See [Configuration](configuration.md#reports) for report settings.

## Reload and Shutdown

On Unix systems:

- `SIGHUP` requests TLS material to be reloaded on the next data store
  reconnect. The process keeps running.
- `SIGINT` and `SIGTERM` request graceful shutdown.

On non-Unix systems, `Ctrl-C` requests graceful shutdown.

Use `SIGHUP` after replacing certificate, private key, or CA certificate files
on disk. The new files are used on the next reconnect. If the reload attempt
cannot establish a working connection, REproduce keeps the last working
connection settings and retries the reload on a later reconnect.

## After Startup

Verify the following after running REproduce:

- Logs show `Data Broker started`.
- Logs show a successful data store connection.
- Input files appear in `File: ...` log lines when they are processed.
- Long-running polling behavior matches the configured polling settings.
- Reports are written under `report_dir` when reporting is enabled.
