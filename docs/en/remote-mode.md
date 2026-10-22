# Remote Mode

In remote mode, REproduce takes its configuration from the Central Manager
(REview) instead of a file. It runs 1 to 64 log collectors over one data store
(Giganto) connection; each collector follows one log file and sends every line
of it as a Giganto `Log` record of the collector's kind.

Remote mode runs on Linux. It is normally installed and started by the Host
Agent, which renders the command line below; you rarely start it by hand.

## Start Command

```bash
reproduce --cert <CERT_PATH> --key <KEY_PATH> --ca-certs <CA_PATHS> \
  --state-dir <DIR> <server_name>@<ip>:<port>
```

<!-- markdownlint-disable MD013 -->

| Argument or flag | Behavior |
| --- | --- |
| `--cert <CERT_PATH>` | Certificate presented to the Central Manager and to Giganto |
| `--key <KEY_PATH>` | Private key of the certificate |
| `--ca-certs <CA_PATHS>` | Comma-separated list of CA certificate files to trust |
| `--state-dir <DIR>` | Directory for checkpoints, created with mode `0700` when missing |
| `<server_name>@<ip>:<port>` | The Central Manager: its TLS server name and address |

<!-- markdownlint-enable MD013 -->

- All four flags and the Central Manager are required. An IPv6 address is
  written in brackets, as `name@[::1]:38390`.
- One certificate is used for both the Central Manager and Giganto.
- REproduce exits with status code `1` when the command line is invalid, when
  the state directory cannot be created or written, or when the certificate,
  key or CA files cannot be read.

## Remote Configuration

The Central Manager serves the configuration as TOML:

```toml
giganto_ingest_srv_addr = "10.0.0.5:38370"
giganto_name = "001.giganto.ds1.customer.example"

[[collectors]]
type = "log"
kind = "nginx_access"
path = "/var/log/nginx/access.log"
start = "end"
```

<!-- markdownlint-disable MD013 -->

| Key | Required | Rule |
| --- | --- | --- |
| `giganto_ingest_srv_addr` | yes | `IP:PORT` of the Giganto ingest server |
| `giganto_name` | yes | Non-empty; the Giganto TLS server name |
| `collectors` | yes | Array of tables, 1 to 64 entries |
| `collectors.type` | yes | `"log"`, the only value |
| `collectors.kind` | yes | Matches `^[a-z0-9][a-z0-9_.-]{0,63}$`; not a named Giganto kind; unique within the configuration |
| `collectors.path` | yes | Path rules below; unique within the configuration |
| `collectors.start` | no | `"end"` (default) or `"beginning"` |

<!-- markdownlint-enable MD013 -->

- Unknown keys at any level are refused, and so is an empty configuration.
- A kind is a label: every collector sends `Log` records with its kind. A kind
  that Giganto reads as another raw event kind, such as `dns`, `conn`, `http`
  or `op_log`, is refused. Clumit Security Web also keeps a kind unique among
  all collectors on a node.
- A path is absolute, at most 4096 bytes, contains no NUL, has no empty, `.` or
  `..` segment and no trailing `/`, and does not lie under
  `/etc/clumit-security`, `/var/lib/clumit-security`, `/opt/clumit-security`
  or `/proc`.
- A configuration that breaks a rule is logged as an error and not applied; the
  configuration already applied keeps running, or REproduce stays idle.

## Lifecycle

- **Idle.** Without a configuration, REproduce collects nothing. It keeps its
  connection to the Central Manager, retrying it every 5 seconds, and fetches
  the configuration again when the Central Manager asks, after each reconnect,
  and on `SIGHUP`. REproduce keeps no copy of its configuration: after a
  restart it is idle until the Central Manager answers.
- **Applying.** A new configuration is applied as a difference. A collector is
  identified by its kind and path. Collectors present in both configurations
  keep running untouched; a changed `start` has no effect on them. Removed
  collectors close their streams (with a close marker, waiting at most 15
  seconds in total for their final acknowledgements), and their checkpoints are
  deleted. A kind kept with a new path is a new collector, which starts afresh.
- **Giganto address change.** A change of `giganto_ingest_srv_addr` or
  `giganto_name` drops the old connection at once and connects to the new
  address. Collectors removed by the same configuration stop without a close
  marker; the others resume from their acknowledged positions on the new
  connection.
- **Failures.** Giganto connection, TLS and handshake failures are retried
  every 5 seconds, and losing the Central Manager does not stop the collectors;
  neither ends the process.
- **Per-collector problems.** A missing, unreadable, refused or non-regular
  file is a problem of its collector alone: it is logged as a warning when the
  collector's state changes and retried every 3 seconds, and the other
  collectors keep running.

## State Directory and Checkpoints

Each log collector saves its checkpoint in
`<state-dir>/checkpoints/log/<kind>.json`:

```json
{"type":"log","kind":"nginx_access","path":"/var/log/nginx/access.log","dev":2049,"ino":131074,"offset":5120}
```

`dev` and `ino` identify the file the collector was reading, and `offset` is
the byte just past the last line Giganto acknowledged.

- A checkpoint is saved at most once per second, and no later than a second
  after it changes; at a clean stop; and whenever a starting position is chosen.
- It is written to `<kind>.json.tmp`, synced to disk and renamed over
  `<kind>.json`. Temporary files an interrupted save left behind are deleted at
  startup.
- A checkpoint saved for another path of the kind is replaced. A corrupt or
  unreadable checkpoint is logged as a warning and treated as a checkpoint at
  the current end of the file, saved before anything is sent, so a damaged
  checkpoint never sends a whole file again.
- A checkpoint that cannot be saved is logged once as a warning and retried
  every 3 seconds; the collector keeps running.

## Signals

- `SIGHUP` marks the TLS files for reload on both connections; each connection
  reads them again when it next reconnects. While idle, it also fetches the
  configuration again.
- `SIGTERM` and `SIGINT` close every stream with its close marker, waiting at
  most 15 seconds in total for the final acknowledgements, save every
  checkpoint and exit with status code `0`.

## Start

- With no checkpoint, `start = "end"` (the default) starts at the end of the
  file and skips its existing content; `start = "beginning"` reads it from its
  beginning.
- A file that does not exist when the collector starts is read from its
  beginning when it appears, whatever `start` says.
- The starting position is chosen when the collector starts, whether or not
  Giganto is reachable, and saved before any line is sent, so a restart before
  the first acknowledgement does not skip lines. While it cannot be saved, the
  collector sends nothing.
- With a checkpoint, `start` is ignored and the collector resumes from the
  checkpoint.

## Following Files

- **Lines.** A line ends at `\n`; a trailing `\r` is dropped and empty lines are
  skipped. Bytes after the last `\n` are held until their `\n` arrives. A line
  longer than 1 MiB is sent in 1 MiB pieces. Lines are sent in batches of at
  most 1000 lines or 4 MiB.
- **Checks.** At the end of the file, the collector checks the path every 3
  seconds.
- **Rename rotation.** When the path names a new file, the collector keeps
  reading the old one until 3 seconds pass with no new bytes in it, sends any
  held bytes as its final line, and then reads the new file from its beginning.
  While the new file cannot be opened, the collector keeps reading the old one,
  where held bytes can still complete their line. The old file stays open,
  unread, until Giganto has acknowledged its last line. A further rotation seen
  meanwhile is followed only after that, so a collector holds at most two files
  open.
- **Copy-truncate.** When the file becomes shorter than the collector has read,
  held bytes are discarded and the file is read again from its beginning once
  that new position is saved.
- **Missing path.** While the path is missing, the collector keeps reading the
  file it has open.
- **Symbolic links.** The path is followed through symbolic links; pointing a
  link at another file is a rename rotation.
- **Refused files.** A file is opened only if it is a regular file and no
  directory above where it really lies is one of `/etc/clumit-security`,
  `/var/lib/clumit-security`, `/opt/clumit-security` or `/proc`, compared by
  identity, so a symbolic link or a moved product directory is refused too. A
  FIFO or a device is refused without blocking the collector.

## Delivery

- Every line is sent at least once. Each collector resumes from the position
  Giganto acknowledged after a reconnect, a stream error or a crash, so lines
  written to a failed stream are read and sent again. A stream that fails while
  lines on it await acknowledgement is replaced at once, even if the file does
  not grow.
- If the file at that position was renamed, the collector finds it in the same
  directory and reads the rest of it before the path. While such a file exists
  but cannot be opened, the collector retries every 3 seconds rather than
  moving on; only when no file holds the position does it read the path from
  its beginning and log that lines may have been lost.
- A reconnect or crash can send up to one acknowledgement window per collector
  again: Giganto's `ack_transmission` lines (1024 by default) plus what was in
  flight, or 60 seconds of lines.
- Within a collector, timestamps strictly increase, so two lines never share a
  Giganto key. A line's event time is the time it was sent.

## When Lines Can Be Lost or Duplicated

- **Copy-truncate.** Lines written after the collector's last read and before
  the truncation exist only in the copy and are lost. A truncation not seen
  because the file grew past the old offset within 3 seconds loses the lines in
  between, and so does one seen but stopped before its new position was saved.
  Lines sent before a truncation was seen and not yet acknowledged, of the
  truncated file or of a rotated-away file still held, are lost if the stream
  then fails.
- **A file replaced in place** by a shorter one with the same inode is treated
  as a truncation.
- **Rename rotation.** A file rotated twice between two checks is never read.
  Bytes written to a renamed file after the collector moved to the new file are
  lost.
- **Inode reuse.** An inode number reused by an unrelated file can be resumed
  at a wrong offset.
- **A final line without `\n`** is held until the file is rotated. It is not
  sent at a stop, and is sent after a restart once complete.
- **Duplicates.** A reconnect or crash sends up to one acknowledgement window
  per collector again.

## Log Lines

<!-- markdownlint-disable MD013 -->

| Level | Line |
| --- | --- |
| `INFO` | `Started collector <kind> for <path>` |
| `INFO` | `Reading <file> for <kind>` (each file a collector opens) |
| `INFO` | `<path> for <kind> was truncated; reading it again from its beginning` |
| `INFO` | `Resuming <file> for <kind> by its inode only` |
| `INFO` | `Stopped collector <kind> for <path> ...` |
| `WARN` | `Collector <kind> for <path>: <reason>; retrying every 3s` |
| `WARN` | `Cannot find the file <kind> was reading before <path>; lines may have been lost` |
| `WARN` | `Sending failed for <kind>: ...` |
| `INFO` | `Sending again for <kind>` (after `Sending failed`) |
| `WARN` | `Cannot save the checkpoint of <kind> to <file>: ...` |
| `INFO` | `Saved the checkpoint of <kind> again` |

<!-- markdownlint-enable MD013 -->

A collector's `<reason>` is one of:

- `the path does not exist`
- `the path is not a regular file`
- `the file lies under the refused directory <dir>`
- `cannot check where the file lies: ...`
- `cannot inspect the path: ...`
- `cannot open the file: ...`
- `cannot read the file: ...`
- `cannot start the reader: ...`
