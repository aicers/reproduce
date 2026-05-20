# Prerequisites

## Requirements

- Certificate, private key, and trusted CA certificates in PEM format
- TOML configuration file
- Giganto server version 0.27.0 or later

## Additional Requirements for Netflow v9 Input

If a Netflow v9 pcap does not contain the templates required to interpret data
records, previously saved template files can be used instead. Template files are
loaded from the path specified by the `NETFLOW_TEMPLATES_PATH` environment variable.

```bash
export NETFLOW_TEMPLATES_PATH=/path/to/netflow_templates
```

Netflow parsing requires the `netflow` feature to be enabled at build time. This
feature is enabled by default.
