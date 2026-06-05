# Prerequisites

Prepare the items below before running REproduce.

## Required Items

- REproduce binary installed on the host that will read the input data.
- Data store server version 0.27.0 or later.
- Network access from the REproduce host to the data store ingest server.
- TOML configuration file.
- Client certificate file.
- Private key file for the client certificate.
- Trusted CA certificate file or files for validating the data store server.
- Read permission for the configured input file, input directory, or Elastic
  dump directory.

## TLS Files

REproduce uses the following configuration fields for TLS:

| Field | File or value |
| --- | --- |
| `cert` | Client certificate file path |
| `key` | Private key file path for the client certificate |
| `ca_certs` | Trusted CA certificate file paths |
| `giganto_name` | Data store server name used for TLS verification |

Each file listed in `ca_certs` may contain one or more PEM-encoded
certificates, such as a CA bundle or a full-chain file.

The `giganto_ingest_srv_addr` value must be an `IP:PORT` socket address. Use
`127.0.0.1:38370` for IPv4-style addresses or `[::1]:38370` for IPv6-style
addresses. Hostnames such as `localhost:38370` are not accepted in this field.

## Input Access

For file mode, the configured `input` value must be readable as a file.

For directory mode, the configured `input` value must be an existing directory
at startup. REproduce processes files under the directory and can optionally
filter them by filename prefix.

For Elastic mode, the configured `dump_dir` must be writable because retrieved
records are stored there before they are transferred.

## Elasticsearch Access

Elastic mode requires:

- Elasticsearch URL.
- Authentication value in `username:password` format.
- Target indices.
- Target Sysmon event codes.
- Start and end timestamps for the query range.
- Writable dump directory.

See [Elastic Mode Configuration](configuration.md#elastic-mode-configuration)
for the required TOML fields.

## Netflow v9 Templates

If a Netflow v9 pcap does not contain the templates required to interpret data
records, provide previously saved template files through the
`NETFLOW_TEMPLATES_PATH` environment variable.

```bash
export NETFLOW_TEMPLATES_PATH=/path/to/netflow_templates
```

Netflow parsing requires the `netflow` build feature. This feature is enabled by
default.
