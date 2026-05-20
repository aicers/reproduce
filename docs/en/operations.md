# Operations

## Execution Command

REproduce runs with a single TOML configuration file path as an argument.

```bash
reproduce <CONFIG_PATH>
```

- `<CONFIG_PATH>`: TOML configuration file path (required)
- `-h`, `--help`: display help
- `-V`, `--version`: display version information

> **Note**
> If no argument or more than one argument is provided, REproduce prints an
> error message and exits.

## File Mode

Run REproduce with a configuration file that specifies a single log file path in
`input`.

```bash
reproduce /path/to/config.toml
```

## Directory Mode

If `input` specifies a directory path, REproduce processes log files in that
directory. If necessary, target files can be filtered using `file_prefix` in the
`[directory]` section.

## Elastic Mode

If `input = "elastic"` is configured and the `[elastic]` section is provided,
REproduce queries the Elasticsearch server and retrieves matching data.

## Polling Mode

If `polling_mode = true` is configured in the `[file]` or `[directory]` section,
REproduce continuously monitors and transfers newly added content.

## Reloading Configuration (SIGHUP)

Sending a `SIGHUP` signal to the running process causes REproduce to
re-establish the Giganto connection during the next reconnect attempt. This can
be used to apply updated configuration without restarting the process.

## Items to Verify After Startup

- Verify that the process does not exit immediately.
- Verify that certificates and configuration files are valid.
- Verify connectivity to the Giganto server.
- Verify that the `"Data Broker started"` log message is displayed.
