# Overview

REproduce is a program that reads log files or packet data, converts them into
events, and sends them to the Giganto server. It can use a single log file, a
directory containing log files, or an Elasticsearch server as its input source.
The input data type is specified in a TOML configuration file.

## Key Features

<!-- markdownlint-disable MD007 -->
- Parses log files or packet data and converts them into events.
- The input source can be one of three types.
    - File mode: reads and sends a single log file
    - Directory mode: reads and sends log files from a directory
    - Elastic mode: queries an Elasticsearch server and sends the retrieved data
- Sends converted events to the Giganto server.
- Supports polling mode to continuously monitor newly appended file content.
- Can generate transfer statistics reports.
<!-- markdownlint-enable MD007 -->

## Input Modes

- **File mode**: specify a log file path in `input`
- **Directory mode**: specify a directory path in `input`
- **Elastic mode**: set `input = "elastic"` and configure `[elastic]` section

> **Note**
> The input type is automatically determined from the `input` value.
> If the value is `"elastic"`, Elastic mode is used. If the path is a
> directory, Directory mode is used. Otherwise, File mode is used.

## Security Assumption (TLS)

REproduce requires certificate-based TLS configuration when communicating with
the Giganto server. The following configuration values must be provided:

- `cert`, `key`, and `ca_certs` for the certificate, private key, and CA certificates
- Each file listed in `ca_certs` may contain one or more PEM certificates, such
  as a CA bundle or full chain

## Manual Map

- **Prerequisites**: Prepare configuration files, certificates/keys, and CA certificates
- **Configuration**: Create and configure the TOML configuration file
- **Operations**: Run REproduce in each input mode
- **Troubleshooting**: Common issues and how to resolve them

## Quick Start

1. Create `config.toml`
2. Prepare the certificate, private key, and CA certificates
3. If using Elastic mode, verify the `dump_dir` path and write permissions
4. Run REproduce. `reproduce <CONFIG_PATH>`
5. Verify connectivity to the Giganto server
6. Verify normal operation through logs
