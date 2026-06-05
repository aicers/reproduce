# Prerequisites

Prepare the items below before running REproduce.

## Preparation Checklist

- REproduce binary installed on the host that will read the input data.
- Data store server compatible with the installed REproduce package.
- Network access from the REproduce host to the data store ingest server.
- TOML configuration file.
- Client certificate file.
- Private key file for the client certificate.
- Trusted CA certificate file or files for validating the data store server.
- Appropriate file and directory permissions for the selected input mode.

## Connection and TLS Preparation

Prepare the data store ingest address, the data store server name used for TLS
verification, and the certificate files needed for the connection.

See [Top-Level Settings](configuration.md#top-level-settings) for the TOML
fields and accepted address format.

## Input Access

For file mode, the configured `input` value must be readable as a file.

For directory mode, the configured `input` value must be an existing directory
at startup. REproduce recursively processes regular files below the directory,
including files reached through symbolic links, and can optionally filter them
by filename prefix.

Elastic mode requirements are listed in the next section.

## Elasticsearch Access

Elastic mode requires:

- Elasticsearch URL.
- Authentication value in `username:password` format.
- Target indices.
- Target Sysmon event codes.
- Start and end timestamps for the query range.
- Writable dump directory for retrieved records.

See [Elastic Mode Configuration](configuration.md#elastic-mode-configuration)
for the required TOML fields.

## Netflow v9 Templates

If a Netflow v9 pcap does not contain the templates required to interpret data
records, provide a previously saved template file through the
`NETFLOW_TEMPLATES_PATH` environment variable.

```bash
export NETFLOW_TEMPLATES_PATH=/path/to/netflow_templates.bin
```
