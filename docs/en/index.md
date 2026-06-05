# Overview

REproduce reads file-based input such as log files or Netflow v5/v9 pcap files,
converts the input into events, and sends those events to a data store ingest
server. When using Elasticsearch as the input source, REproduce retrieves
Sysmon event data.

Use this manual when you need to prepare the runtime environment, write a
configuration file, run REproduce, understand runtime behavior, or diagnose a
startup or transfer problem.

## What REproduce Does

- Reads file-based input from a single file or directory.
- Retrieves Sysmon event data when Elasticsearch is used as the input source.
- Converts supported input formats into events accepted by the data store.
- Sends converted events to a data store ingest server over TLS.
- Supports polling for appended data or newly added files.
- Can write transfer statistics reports.
- Can resume from a saved transfer position when checkpointing is configured.

## Input Modes

REproduce chooses the input mode from the top-level `input` value in the TOML
configuration file.

- `input = "elastic"`: Elastic mode.
  Queries Elasticsearch and sends the retrieved Sysmon data.
- Existing directory path: Directory mode.
  Processes files under the directory.
- Any other path: File mode.
  Processes the value as a single input file.

## Security Assumption

Communication with the data store requires TLS configuration. The configuration
must include a client certificate, its private key, trusted CA certificates, the
data store ingest address, and the data store server name used for TLS
verification.

See [Prerequisites](prerequisites.md) for the files and access required before
running REproduce.

## Manual Map

- [Prerequisites](prerequisites.md): Prepare certificates, input access,
  Elasticsearch access, and Netflow templates.
- [Configuration](configuration.md): Write the TOML file and choose `kind`,
  input mode, polling, checkpoints, logging, and reports.
- [Operations](operations.md): Run REproduce, check lifecycle logs, understand
  polling behavior, and handle reload or shutdown.
- [Troubleshooting](troubleshooting.md): Diagnose startup, configuration,
  connection, and input problems.

## Quick Start

1. Complete the items in [Prerequisites](prerequisites.md).
2. Create a TOML file using [Configuration](configuration.md).
3. Run REproduce with the configuration path:

```bash
reproduce /path/to/config.toml
```

After startup, check the logs for `Data Broker started` and
`Connected to data store ingest server at ...`. If startup or transfer fails,
use [Troubleshooting](troubleshooting.md).
