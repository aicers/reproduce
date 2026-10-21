<!-- markdownlint-configure-file {
  "MD013": { "tables": false, "code_blocks": false }
} -->

# RFC 0001: REproduce as a Clumit Security module

Status: accepted (2026-10-21).

This RFC makes REproduce (this repository) the log collector of Clumit Security:
packaged by bootler as a Security module, installed through Clumit Security Web
→ Central Manager (REview) → Host Agent (roxyd) like Piglet, Hog and Crusher,
and configured from Clumit Security Web in remote mode. Every item marked
**[DECISION]** is settled; no design question remains open.

Revisions this RFC was written against: reproduce `ff2f0f2e` (= 0.25.1), bootler
`8de40c3b`, deploy-core `c9f776bd` (bootler's pin; roxyd pins `b4e645a3`), roxyd
`51a5820c`, review `510cd278` (0.61.0+3, linking review-protocol 0.21.0
`76e28fe`), review-database `ab7df279`, review-web 0.44.0 (`dcadae63`),
aice-web-next `7df1f3b3`, giganto `e9656134` (0.31.0+3), giganto-client 0.28.0,
crusher 0.10.0 (`19e57e15`). Every `path:line` below is at these revisions.

## 1. Summary

1. **Remote mode.** REproduce gains a second invocation, `reproduce --cert
   <path> --key <path> --ca-certs <paths> --state-dir <dir> <manager endpoint>`,
   that takes its configuration from REview over review-protocol (`get_config`,
   `update_config`), like Crusher. `reproduce <CONFIG>` keeps working unchanged.
2. **A list of log collectors per instance.** The remote configuration carries
   one Giganto connection and 1 to 64 collectors, each reading one log file into
   one Giganto `Log` kind.
3. **Following live log files.** Remote-mode collectors follow a growing file
   across rename and copy-truncate rotation, never split a line being written,
   and keep their acknowledged position as `(device, inode, byte offset)` under
   the state directory. Delivery is at least once.
4. **Packaging and plumbing.** bootler packages REproduce; deploy-core lets a
   unit declare the `adm` supplementary group so the collector can read
   `/var/log`; review-database, review-web and review learn a `LogCollector`
   agent kind and the `reproduce` package; Clumit Security Web gets a Log
   Collector form and a helper that lists every applied log kind for the
   Unsupervised Engine's training form.

## 2. Motivation and current state

The Unsupervised Engine's (REconverge) prefix analysis reads Giganto `Log`
events only, and logs reach Giganto only through REproduce. bootler's README
names REproduce among the modules installed through the UI (bootler
`README.md:10-14`), but nothing installs it today, so no log source exists in a
deployed product.

### 2.1 REproduce 0.25.1

- One positional argument, the configuration path
  (`src/bin/reproduce/main.rs:75-85`, `:106-128`). No review-protocol dependency
  and no manager connection (`Cargo.toml`). Configuration is read once at start
  (`main.rs:88-91`).
- One process is one collector: a single `kind` and a single `input`
  (`src/bin/reproduce/config.rs:101-114`) next to the shared Giganto block
  `cert`, `key`, `ca_certs`, `giganto_ingest_srv_addr` (`IP:PORT` only),
  `giganto_name` (the Data Store's TLS server name) (`src/config.rs:6-32`).
- `kind` selects the parser: Zeek, `oplog`, Sysmon, Netflow and eleven
  security-device names are structured; any other non-blank string is an
  unstructured log kind (`main.rs:525-545`), and only that case sends
  `RawEventKind::Log` (`src/collector/log.rs:80-84`), one `Log { kind, log }`
  per line (`log.rs:129-132`). A log kind spelled like a reserved name (`dns`)
  silently selects a structured parser.
- Each line is stamped with `Timestamp::now()` when sent (`log.rs:134-135`), one
  line per batch, with no de-duplication (Zeek and Sysmon use
  `apply_timestamp_dedup`, `src/collector/zeek.rs:141`,
  `src/collector/sysmon_csv.rs:144`).
- File polling keeps the first open handle and waits at EOF every 3 s
  (`log.rs:107-115`, `src/collector.rs:25`). Nothing reopens the path or checks
  its size, so rename rotation loses everything after the rename and
  copy-truncate loses lines until the file outgrows the old offset.
  `read_until(b'\n')` returns a line still being written, which is then sent in
  two pieces (`log.rs:178-192`).
- Directory polling reads each file to EOF once and never revisits it
  (`log.rs:107-118`, `main.rs:844-899`); the processed list is in memory
  (`main.rs:852`, `:890`).
- The checkpoint is a line count in `{input}_{suffix}` next to the input
  (`src/checkpoint.rs:54-63`), written only after a file's run ends
  (`main.rs:1021-1041`, `:1099-1105`). A batch counts as sent once it is written
  to the stream (`src/controller.rs:96-127`); a batch written to a connection
  that then fails is never re-sent.
- `SIGHUP` sets one shared reload flag that the next successful reconnect clears
  (`src/sender.rs:389-406`); `SIGINT`/`SIGTERM` stop gracefully
  (`main.rs:1133-1198`). Only a connect timeout is retried; other connect errors
  end the run (`src/sender.rs:373-445`, `:576-614`).
- Giganto 0.31.0 accepts it: REproduce sends protocol version `0.28.0`
  (`src/sender.rs:39-40`, `:542`) and Giganto admits ingest clients
  `>=0.27.0,<0.32.0` (giganto `src/comm/ingest.rs:76`).

### 2.2 Giganto

- The sensor name is the SAN's `service.host.domain`; the instance number is
  dropped (giganto `src/server.rs:167-170`, `:206-255`;
  `src/comm/ingest.rs:450-452`). Every REproduce on a host is the one sensor
  `reproduce.<host>.<domain>`.
- A `Log` is stored under `sensor | kind | timestamp` (giganto
  `src/comm/ingest.rs:1316-1326`); `kind` is free-form and two records with the
  same key overwrite each other.
- Each bidirectional stream on an ingest connection is served by its own task
  (giganto `src/comm/ingest.rs:510-535`); quinn's default of 100 concurrent
  bidirectional streams per connection is left unchanged (giganto
  `src/server.rs:36-52`). A connection's close marks the sensor disconnected
  (`ingest.rs:498-521`).
- Giganto acknowledges a stream with the timestamp of the last appended event
  every `ack_transmission` records (default 1024) and at least every 60 s
  (giganto `src/comm/ingest.rs:71`, `:1262-1271`, `:1443-1455`), and answers a
  stream's close marker with the timestamp `-1` after everything before it has
  been appended (`:1304-1313`). REproduce's ACK receiver only logs these today
  (`src/sender.rs:755-780`).
- No query lists log kinds (`logRawEvents` requires a kind, giganto
  `src/graphql/log.rs:217-232`). Customer-data deletion already accepts
  `reproduce.*` (giganto `src/graphql/customer_deletion.rs:951`).

### 2.3 Packaging and the Central Manager

- bootler stages `reproduce` by name (`core/src/product.rs:271-278`) but leaves
  it out of `PACKAGE_REGISTRY` and the spec catalogue because "its module class
  is undecided" (`product.rs:364-369`, `:1096-1105`; bootler RFC 0004
  `docs/rfcs/0004-module-packaging-and-core-extraction.md:189-194`). This RFC
  decides that class (§4.8).
- Remote-mode modules run `ExecStart = <bin> --cert --key --ca-certs
  [--state-dir state] <manager endpoint>` with no `-c` (`product.rs:795-853`),
  as `clumit-security` (Piglet as root, `:967`), idle until REview pushes a
  configuration.
- review-database's `AgentKind` has Unsupervised, Sensor, SemiSupervised,
  TimeSeriesGenerator (`src/tables/agent.rs:30-57`); REview lists `reproduce` as
  "deliberately unpackaged" (review `src/store/identifier.rs:15-38`, `:50-51`).
  REview's `get_config` is kind-agnostic: it maps the peer SAN to the node by
  hostname and the agent by key and returns its stored `config`, or an error
  when there is none (review `src/agent/requests.rs:497-522`). An agent's
  handshake must advertise a review-protocol *protocol* version, `>=0.48.0` and
  at most `0.49.0` (review `src/agent.rs:84-94`), which is
  `review_protocol::PROTOCOL_VERSION` (`0.49.0` at review-protocol 0.21.0), not
  a REview crate version.
- roxyd installs any non-core package generically (roxyd
  `src/handlers/classify.rs:10-22`) and renders units with deploy-core
  (`src/handlers/package/apply.rs:1635`). Each module's key, certificate, CA
  bundle and bootroot `secret_id` live in
  `<etc_dir>/agent/<service>/<instance>/` (roxyd `src/state/paths.rs:551-627`),
  readable by the product account.
- deploy-core stamps its `format_version` on every manifest it writes, whatever
  the contents, refuses a manifest outside `MIN..=MAX` (currently 3..=7), and
  asserts at compile time that `MAX` equals the version it writes (deploy-core
  `src/manifest.rs:20-44`, `:986-990`, `:1630`). It has raised the version for
  each additive `UnitTemplate` field (`limit_nofile`, `run_as`). So with today's
  rule, a release that raises the version is refused as a whole — the Host
  Agent's own update package included — by every reader built before it. bootler
  has not shipped a versioned release yet (`CHANGELOG.md` holds only
  `[Unreleased]`), so no deployed reader is older than the current format.
- roxyd reports the format range it reads at every handshake
  (`manifest_formats`, roxyd `src/control/metadata.rs:244-248`); REview records
  it per host (review `src/agent.rs:462`, `src/trust/state.rs:51`, `:434`) and
  today uses it only for trust generations (activation
  `src/trust/activation.rs:398-427`, per-host delivery
  `src/trust/delivery.rs:385-392`). Package installs and updates are sent
  without that check (`src/deploy/apply.rs:1091-1110`). Both roxyd and REview
  link deploy-core: REview checks every uploaded package with `verify_upload`
  (review `src/store/verifier/shared.rs:24-26`, `:349`) at deploy-core 0.2.0
  (`b4e645a3`, review `Cargo.lock:1124-1128`).
- Clumit Security Web has no REproduce form; its module and agent-kind lists are
  hard-coded (§4.10). It can already read every agent's `config` (`nodeList`,
  aice-web-next `src/lib/node/queries/node-fields.graphql:28-46`).

## 3. Scope

In scope: everything in §4 across aicers/reproduce, aicers/deploy-core,
aicers/roxyd, aicers/bootler, aicers/review-database, aicers/review-web,
aicers/review and aicers/aice-web-next.

Not in scope:

- Structured inputs in remote mode (Zeek, Sysmon, Netflow, security-device logs,
  `oplog`, Elastic, Giganto export import). They stay available through
  `reproduce <CONFIG>`.
- Any change to local mode (`reproduce <CONFIG>`): its parsing, polling,
  delivery and checkpoint behaviour stay as they are.
- Directory or glob inputs in remote mode; reading compressed rotations (`.gz`);
  deleting or retaining log files (logrotate's job); parsing a time out of a log
  line (the send time stays the event time); a syslog receiver; collectors on
  hosts roxyd does not manage (Windows).
- Per-collector status in the UI; the module's own logs go to the journal (no
  `log_path` is emitted).
- Collecting while REview is unreachable at startup (§4.3).
- Customer-data deletion of REproduce data driven from REview.
- The Unsupervised Engine's training form itself; this RFC only provides the
  helper it consumes (§4.10).
- No Giganto or petabi/reconverge change.
- Releases (version bump, tag, changelog section) and deployment checks are
  human steps, not issue work. "Depends on N" in §8 means on N's published
  release tag; for aice-web-next, which bootler pins by commit, on N's merge
  commit.

## 4. Design

### 4.1 Invocation

- **[DECISION] Two invocations, told apart by their flags.**
  - Local mode, unchanged: `reproduce <CONFIG>` (exactly one positional argument
    and no flags other than `-h`/`-V`).
  - Remote mode: `reproduce --cert <CERT_PATH> --key <KEY_PATH> --ca-certs
    <CA_PATHS> --state-dir <DIR> <MANAGER>`. `--ca-certs` takes a
    comma-separated list (as Crusher, crusher `src/main.rs:146-172`).
    `<MANAGER>` is `<server_name>@<ip>:<port>`, the form bootler renders
    (`core/src/product.rs:799-806`).
  - If any of the four flags is present, all four and `<MANAGER>` are required.
    An invocation that mixes a configuration path with any flag, misses a flag,
    or whose positional argument is not a manager endpoint exits with status 1
    and a message naming the two forms. `-h` prints both forms.
- **[DECISION] The binary stays `reproduce`.** bootler requires the process file
  name to equal the package id (`core/src/product.rs:1055-1073`, asserted at
  `:4004-4050`), so remote mode is not a separate binary.
- **[DECISION] `--state-dir`** is resolved against the working directory and
  created with mode 0700 when missing (as Piglet and Hog; bootler passes the
  literal `state` with `WorkingDirectory=` set to the instance data directory,
  `product.rs:829-853`). REproduce refuses to start when it cannot create or
  write it.

### 4.2 Remote configuration

- **[DECISION] Schema.** The string REview returns from `get_config` is TOML:

  ```toml
  giganto_ingest_srv_addr = "10.0.0.5:38370"
  giganto_name = "001.giganto.ds1.customer.example"

  [[collectors]]
  type = "log"
  kind = "nginx_access"
  path = "/var/log/nginx/access.log"
  start = "end"
  ```

  | Key | Required | Rule |
  | --- | --- | --- |
  | `giganto_ingest_srv_addr` | yes | `IP:PORT` (same parser as local mode, `src/config.rs:25-32`) |
  | `giganto_name` | yes | non-empty; the Data Store's TLS server name |
  | `collectors` | yes | array of tables, 1 to 64 entries (Giganto serves at most 100 concurrent streams per connection, §2.2) |
  | `collectors.type` | yes | `"log"` (the only value) |
  | `collectors.kind` | yes | matches `^[a-z0-9][a-z0-9_.-]{0,63}$`; not a named Giganto kind (below); unique within the configuration |
  | `collectors.path` | yes | §4.2 path rules; unique within the configuration |
  | `collectors.start` | no | `"end"` (default) or `"beginning"` |

  Unknown keys at any level are refused. An empty string is an invalid
  configuration (review-database accepts `""` as a TOML table,
  `src/tables/node.rs:44-55`). Certificates come from the command line, never
  from this string.
- **[DECISION] Path rules.** A path is absolute, at most 4096 bytes, contains no
  NUL, has no empty, `.` or `..` segment and no trailing `/`. It must not lie
  under `/etc/clumit-security`, `/var/lib/clumit-security`,
  `/opt/clumit-security` or `/proc`. These rules are checked by Clumit Security
  Web at save (§4.10) and by REproduce when it parses a configuration; REproduce
  also checks the opened file (§4.5).
- **[DECISION] In remote mode `kind` is a label only.** It is never passed to
  `classify_kind`; every remote collector sends `RawEventKind::Log` with `Log {
  kind, log }`.
- **[DECISION] A kind must not be a named Giganto kind.** Giganto resolves a
  requested kind with `RawEventKind::from_str` before reading (giganto
  `src/comm/publish.rs:1231`), so `Log` records stored under a name it parses as
  another kind (`dns`, `conn`, `http`, `op_log`, `netflow5`, `timeseries`,
  `dns_event`, …) could never be read back as logs, and aice-web-next RFC 0006
  refuses such kinds for prefix training. A kind for which giganto-client
  0.28.0's `RawEventKind::from_str` (aliases included, `src/lib.rs:35-85`;
  case-sensitive, which the lowercase pattern makes moot) returns anything other
  than `Log` or an error is refused, by REproduce when it parses a configuration
  and by Clumit Security Web at save.
- **[DECISION] Collector identity is `(kind, path)`.** Two configurations name
  the same collector when both match.

### 4.3 Remote-mode lifecycle

- **[DECISION] Follow Crusher's manager client** (crusher
  `src/request.rs:185-250`, `:395-440`, `src/main.rs:410-440`): connect with
  review-protocol's `ConnectionBuilder`, agent name `reproduce`
  (`CARGO_PKG_NAME`), version `CARGO_PKG_VERSION`, protocol version
  `review_protocol::PROTOCOL_VERSION` of the linked tag (no hard-coded REview
  version), and status `Idle` while no configuration is applied, `Ready`
  otherwise. Call `get_config`; serve `update_config` by re-fetching the
  configuration. Link the review-protocol tag REview links (0.21.0 at REview
  0.61.0).
- **[DECISION] Idle until a configuration exists.** When REview is unreachable
  or `get_config` fails (REview answers "config unavailable" for an instance
  never applied, review `src/agent/requests.rs:513-520`), REproduce stays
  running, retries the connection, and waits for `update_config`, `SIGHUP` or a
  termination signal, as Crusher's idle mode does (crusher
  `src/request.rs:236-310`). REproduce keeps no local copy of its configuration:
  after a restart it collects nothing until REview answers, and its checkpoints
  are kept.
- **[DECISION] Applying a configuration.**
  - Applies are serialized. An `update_config` that arrives during an apply
    schedules exactly one more fetch after it (a coalescing notification, as
    Crusher's).
  - A configuration that fails to parse or validate is rejected with an error
    log line; the collectors already running keep running with the previous
    configuration. With no previous configuration REproduce stays idle.
  - A valid configuration is applied as a difference: collectors whose `(kind,
    path)` is new start; collectors no longer present finish their streams
    concurrently (close marker and final ACK, waiting at most
    `CHANNEL_CLOSE_TIMEOUT`, 15 s, in total, `src/sender.rs:31`) — or, when the
    same apply changes the Giganto address, stop at once without a close marker
    — and stop **without saving a checkpoint**; only then do new collectors
    start. Collectors present in both keep running untouched (a changed `start`
    has no effect on them). Then the checkpoint files and temporary files
    (`<kind>.json`, `<kind>.json.tmp`) of kinds not in the configuration are
    deleted. At startup, before any collector starts, every `*.json.tmp` file is
    deleted.
  - A change to `giganto_ingest_srv_addr` or `giganto_name` cancels every
    in-flight connect and send at once, drops the old connection, and connects
    to the new address. Each collector then resumes from its last acknowledged
    position (§4.6).
- **[DECISION] Losing REview does not stop collectors.** They keep running with
  the applied configuration while the manager connection reconnects.
- **[DECISION] A file problem is per collector.** A missing, unreadable, refused
  (§4.5) or non-regular path is logged as a warning and retried every 3 s; other
  collectors and the instance keep running.
- **[DECISION] Giganto problems never end the process in remote mode.** Any
  connect, TLS or handshake failure is logged and retried every 5 s, without
  limit; a newer apply cancels the retry. Collectors stop reading while their
  connection is down.
- **[DECISION] Signals.** `SIGHUP` sets one reload flag per connection (manager
  and Giganto); each connection clears only its own flag when it next reconnects
  with the reloaded material. While idle, `SIGHUP` also triggers a `get_config`
  retry. `SIGTERM`/`SIGINT` stop every collector, finish all streams
  concurrently (waiting at most `CHANNEL_CLOSE_TIMEOUT`, 15 s, in total, for
  their final ACKs), save checkpoints, close both connections and exit 0.

### 4.4 Giganto connection

- **[DECISION] One QUIC connection per instance, one stream per collector.**
  Opening one connection per collector would register the same sensor several
  times, and closing one would mark the sensor disconnected while others still
  send (giganto `src/comm/ingest.rs:498-521`). Each collector opens its own
  bidirectional stream with a `Log` record header on the shared connection;
  Giganto serves each stream in its own task (`:510-535`).
- **[DECISION] Split `GigantoSender`** into a per-instance connection owner
  (endpoint, TLS reload, reconnect) and a per-stream sender (header, batches,
  ACK receiver, close). The owner reconnects single-flight under a generation
  number: a stream that sees a write error on generation *g* asks the owner for
  a connection newer than *g* and never closes a newer one. A stream-level error
  on a live connection reopens only that stream. Local mode keeps one connection
  and one stream and behaves exactly as today.

### 4.5 Following a log file

All rules in this section apply to remote-mode collectors only.

- **[DECISION] Position.** A collector's position is `(dev, ino, offset)`: the
  device and inode of the file it is reading, and the byte offset just past the
  last complete line it has handled.
- **[DECISION] Opening.** The collector `stat`s `path` and refuses anything that
  is not a regular file, then opens it with `O_RDONLY | O_NONBLOCK | O_NOCTTY |
  O_CLOEXEC` and checks the open descriptor: it must be a regular file
  (`fstat`), and no ancestor directory of its real path (read from
  `/proc/self/fd/<n>`) may have the `(dev, ino)` of a refused directory. The
  refused directories are the four of §4.2 (the `clumit-security` namespace),
  `stat`ed once at startup; one that does not exist is skipped. Comparing
  directory identities rather than path strings catches symlinks, relocated
  (symlinked) product directories and bind mounts alike, and covers every
  module's key, CA bundle and bootroot `secret_id`, which all live under
  `/etc/clumit-security` (roxyd `src/state/paths.rs:551-627`) — except through a
  hard link placed elsewhere, which `fs.protected_hardlinks` allows only to a
  file's owner or to a user who can already read and write it. The list of
  refused directories is a parameter of the check so tests can use temporary
  directories. A failed check closes the descriptor and is a per-collector
  warning (§4.3), logged when the collector's state changes rather than every 3
  s.
- **[DECISION] Reading runs off the async runtime** (one blocking task per
  collector), so a stalled file system cannot stall the manager connection or
  other collectors.
- **[DECISION] Start.** The first open and the start position are taken when the
  collector starts, independent of the Giganto connection. With no checkpoint:
  if `path` exists at the collector's first attempt, the collector begins at the
  file's end once it can open it (`start = "end"`) or at 0 (`start =
  "beginning"`); if `path` does not exist at the first attempt, the file is read
  from 0 when it appears, whatever `start` says. In every case the collector
  saves its starting position `(dev, ino, offset)` as soon as it has opened the
  file, so a restart before the first acknowledgement does not skip lines. With
  a checkpoint, `start` is ignored.
- **[DECISION] Lines.** A line ends at `\n`; a trailing `\r` is dropped and
  empty lines are skipped (as today, `log.rs:96-101`, `:183-188`). Bytes after
  the last `\n` are held and not sent until their `\n` arrives. A line longer
  than 1 MiB is sent in 1 MiB pieces.
- **[DECISION] At EOF, every 3 s,** the collector `stat`s `path` (following
  symlinks) and compares it with the open file:
  - same `(dev, ino)` and size ≥ offset: read again;
  - same `(dev, ino)` and size < offset (copy-truncate): continue from offset 0
    of the same file; held partial bytes are discarded;
  - different `(dev, ino)` (rename rotation): keep reading the old handle until
    one full 3 s interval passes with no new bytes on it (the producer may still
    write to the renamed file until it reopens), then send any held partial
    bytes as a final line, open `path` (with the opening checks) and read it
    from offset 0. The old handle stays open, unread, until the acknowledged
    position (§4.6) has moved past it. A further rotation detected while a
    rotated-away handle is still held is not followed until that handle is
    released, so at most two handles are open per collector;
  - `path` missing: keep reading the open handle and check again at the next
    interval.
- **[DECISION] Timestamps are strictly increasing per collector:** `max(now,
  previous + 1)` in nanoseconds, so two lines never share a Giganto key (`sensor
  | kind | timestamp`). The previous timestamp is not persisted. The event time
  stays the send time.
- **[DECISION] Batching.** A batch holds at most 1000 lines or 4 MiB of line
  bytes, whichever comes first; a partial batch is sent when the collector
  reaches EOF.
- **[DECISION] Resuming** from a position `(dev, ino, offset)` — at restart or
  after a reconnect —:
  - if the collector still holds an open handle with that `(dev, ino)` (a
    rotated-away file, above), resume on it at `offset`, then continue with
    `path` from 0;
  - if `path` has the same `(dev, ino)`, resume at `offset` (or at 0 if the file
    is now shorter than `offset`); if only the inode matches (device numbers can
    change across reboots on some file systems) and the file is at least
    `offset` long, resume at `offset` and log it;
  - otherwise look in the directory of the file the collector last opened (its
    real path from `/proc/self/fd`, which differs from `path`'s directory when
    `path` is a symlink) — at restart, when nothing has been opened yet, the
    directory of `path`'s real path if `path` resolves, else `path`'s parent —
    with `lstat` and the opening checks, for a regular file with that `(dev,
    ino)` — or that inode alone, under the inode-only rule above (the renamed
    predecessor); if found, read it from `offset` to EOF and then `path` from 0;
    if not found, log a warning that lines may have been lost and read `path`
    from 0.

### 4.6 Checkpoints and delivery

- **[DECISION] At-least-once delivery, acknowledged positions.** Each stream
  keeps, in memory, the timestamp of the last line of every batch it has written
  with the position just past that line. The ACK receiver task passes each
  acknowledged timestamp to its stream's queue: a data timestamp acknowledges
  every entry up to it; the close ACK (`-1`) acknowledges every entry written on
  that stream; if no close ACK arrives within `CHANNEL_CLOSE_TIMEOUT` (15 s) of
  the close marker, the stream keeps its last data acknowledgement. Entries of
  an earlier stream are dropped when a stream is reopened. The acknowledged
  entry's position becomes the stream's acknowledged position. When every
  written entry is acknowledged and the reader holds no unsent lines or partial
  bytes, the acknowledged position is the reader's current position, so right
  after a rotation with nothing pending it becomes `(new dev, new ino, 0)` and
  the rotated-away handle is closed; otherwise it is the position just past the
  last acknowledged line. Whenever a collector's stream is (re)opened — after a
  stream error, a reconnect, or an address change — the collector resumes from
  its acknowledged position (§4.5 Resuming), so lines written to a failed stream
  are read and sent again. Re-sent lines get new timestamps, so Giganto stores
  them again: a reconnect or crash can duplicate up to one acknowledgement
  window (`ack_transmission` lines, default 1024, plus what was in flight, or 60
  s of lines) per collector, and never loses an acknowledged line unless Giganto
  itself crashes before flushing its write-ahead log: Giganto acknowledges
  before its WAL flush (giganto `src/storage.rs:633-636`, `:1530`;
  `src/comm/ingest.rs:1264`, `:1451`, `:1459`), and no Giganto change is in
  scope. Local mode keeps its existing policy (reproduce discussion #797).
- **[DECISION] Location.** `<state-dir>/checkpoints/<kind>.json` (a kind is
  unique within a configuration and filename-safe by its pattern). The file
  holds `{"kind": …, "path": …, "dev": …, "ino": …, "offset": …}`. A file whose
  `path` differs from the collector's is treated as no checkpoint and
  overwritten.
- **[DECISION] Writing.** A collector saves its acknowledged position at most
  once per second and no later than one second after it last changed, and always
  on a clean stop (except a collector removed by an apply, §4.3) and when a
  collector with no checkpoint first opens its file (§4.5 Start). The file is
  written to `<kind>.json.tmp` in the same directory, `fsync`ed, renamed over
  `<kind>.json`, and the directory is `fsync`ed.
- **[DECISION] A corrupt or unreadable checkpoint** is logged and treated as a
  checkpoint at the current end of `path`, so a damaged file never causes a
  whole file to be sent again.

### 4.7 Identity and certificates

- **[DECISION]** REproduce presents its bootroot certificate
  (`<instance>.reproduce.<host>.<domain>`) to both REview and Giganto. REview
  finds its configuration by that SAN; Giganto names its data
  `reproduce.<host>.<domain>`. No REproduce-side name setting exists.
- **[DECISION] Kind uniqueness is per host.** Because every REproduce instance
  on a host is the one Giganto sensor, a kind must be unique among all
  collectors of all REproduce instances on one node. REproduce enforces
  uniqueness within its own configuration (§4.2); Clumit Security Web enforces
  it across the node (§4.10). The same kind on different hosts is expected (e.g.
  `nginx_access` on several web servers), matching the Unsupervised Engine's
  detectors, which take one kind and many sensors.

### 4.8 Packaging (bootler, deploy-core, roxyd)

- **[DECISION] Module class:** a `native-binary` `PackageKind::Module` with
  `Multiplicity::ManyPerHost` and `PlacementClass::ModuleHosts`, like the other
  five (`core/src/product.rs:373-429`, `:1055-1073`). Usually one instance per
  host; more are allowed and share the host's kind namespace (§4.7).
- **[DECISION] Recipe:** a `[[component]]` `reproduce` in
  `versions/components.toml`, `product = "bootler-security"`, `repo =
  "https://github.com/aicers/reproduce.git"`, `ref`/`version` = the REproduce
  release that ships §4.1-§4.6, `build = cargo build --release
  --no-default-features` with the promoted-locals `--config` flag every Rust
  recipe carries (`versions/components.toml:18-20`), `kind = "native-binary"`,
  `dispositions = ["stage"]`, `artifact = "target/release/reproduce"`,
  `archive_path = "modules/reproduce.pkg"`. `--no-default-features` drops
  `netflow` and so libpcap; in this build a `netflow5`/`netflow9` kind in local
  mode is treated as an unstructured log kind.
- **[DECISION] Unit (`REPRODUCE_UNIT`):** `HOG_UNIT` (`product.rs:992-1008`)
  with its own description and `supplementary_groups: [Adm]` — so
  `STATE_DIR_MODULE_EXEC_START` (`:842-853`), the same After/Wants/WantedBy and
  Restart, `ExecReload` = `MODULE_EXEC_RELOAD`, `WorkingDirectory` = DataDir, no
  environment, runs as the product account `clumit-security` (no `run_as`),
  `ProtectHome`, `PrivateTmp`, `NoNewPrivileges` as every module, plus
  `SupplementaryGroups=adm`. Rendered (certificate paths elided):

  ```text
  User=clumit-security
  SupplementaryGroups=adm
  ExecStart=/opt/clumit-security/bin/reproduce --cert … --key … --ca-certs … --state-dir state 001.review.h1.customer.example@10.0.0.1:38390
  ExecReload=/bin/kill -HUP $MAINPID
  WorkingDirectory=/var/lib/clumit-security/modules/reproduce/001
  ```

- **[DECISION] Why `adm`:** Ubuntu's logs are mostly owned `root`, `syslog` or
  `www-data` with group `adm`, mode 0640. Granting the group per unit leaves the
  `clumit-security` account without supplementary groups, which bootler requires
  of the account (`core/src/accounts.rs:192-193`, `:411-416`). Accepted
  consequence: a configuration pushed from REview can send to Giganto any file
  readable by `clumit-security` or `adm` outside the refused prefixes (§4.2,
  §4.5); that is the module's purpose. `ProtectHome` stays, so files under
  `/home` cannot be read.
- **[DECISION] deploy-core gains the field.** `UnitTemplate`
  (`src/module_spec.rs:92-151`) gets `supplementary_groups:
  Vec<SupplementaryGroup>`, `#[serde(default, skip_serializing_if =
  "Vec::is_empty")]`, where `SupplementaryGroup` is a compile-time enum with the
  single variant `Adm` (package data can name only what the enum offers, as with
  `RunAs`). It serializes as `"adm"` (lowercase, as `RunAs`'s `"root"`).
  Validation refuses a duplicated group and refuses groups together with
  `run_as`. The renderer emits one `SupplementaryGroups=` line immediately after
  the `User=` line; rendering a unit that declares groups but would render no
  `User=` line (no account supplied) is a typed render refusal, never a silently
  dropped line. The render-order documentation (`src/module_spec.rs:66-80`)
  names the new line. `MANIFEST_FORMAT_VERSION` becomes 8; when is decided by
  the readers-first rule below.
- **[DECISION] Readers first, as a standing deploy-core rule.** A manifest
  format change ships in two steps: first a release whose readers (roxyd,
  REview) understand version *V* while every writer still stamps *V−1*; then, in
  a later release, writers stamp *V*. Content introduced at *V* is refused in a
  manifest stamped below *V*, so step 1 cannot leak it to older readers: here
  `SUPPLEMENTARY_GROUPS_FORMAT_VERSION = 8`, a non-empty group list in a
  manifest stamped below it is a validation error, and it is asserted `<=
  MAX_MANIFEST_FORMAT_VERSION` (the image-declaration gate is the precedent for
  refusing content below its version, `src/manifest.rs:619`; note its existing
  assert, `:1635`, compares with the written version, not `MAX`). The window
  check in the test at `src/manifest.rs:1620-1635` becomes a `const fn`
  predicate, true for `MAX == CURRENT` or `MAX == CURRENT + 1`, with unit tests;
  the doc comments at `:21-26` and `:39-44` and the test's name state the rule
  instead of "this build reads what it writes". Step 1 may be skipped only when
  no released consumer reads below *V*. The bootler release that *adds readers*
  of a new version is marked in bootler's release notes as one that cannot be
  skipped. bootler's `docs/release.md` ("Raising the manifest `format_version`
  floor", `:1979-2006`) states the rule and replaces its "tooling writes 7"
  sentences, and also says that once writers stamp *V*, every new trust
  generation is stamped *V* and REview refuses to activate it while any
  push-eligible host reports a lower maximum (review
  `src/trust/activation.rs:398-427`, per-host delivery
  `src/trust/delivery.rs:385-392`), so key revocations and build withdrawals
  wait for every Host Agent to read *V*.
- **[DECISION] Applying it to this RFC: one step.** No versioned bootler release
  has shipped (§2.3), so no released consumer reads below 8 and step 1 is
  skipped: deploy-core goes to `MANIFEST_FORMAT_VERSION =
  MAX_MANIFEST_FORMAT_VERSION = 8` in one release (§8 item 7). The one-step path
  holds only while no versioned bootler release ships with a roxyd or REview
  that reads below format 8: the first versioned bootler release after §8 item 7
  must carry the roxyd and review releases of §8 items 8 and 11. If any
  versioned bootler release ships before that with an older roxyd or REview pin,
  the hosts it reaches need a readers release, and the RFC is revised to the
  two-step path before work continues.
- **[DECISION] Release order.** deploy-core, then roxyd and review with the new
  pin, then bootler (§8 item 13), which carries those roxyd and review releases
  in the same change. Before installing REproduce, operators update the REview
  host with `bootler-security update` and each module host's roxyd through the
  UI; REview's format check (§4.9) refuses, with a reason, any package a host's
  roxyd cannot read.
- **[DECISION] bootler bookkeeping.**
  - Bump deploy-core; bump the payload recipe pins of `roxyd`, `review` and
    `aice-web-next` (`versions/components.toml:501-503`, `:535-537`, `:603-605`)
    to the releases from §8 items 8, 11 and 12, in the same change as the rest
    of this bookkeeping (§8 item 13), so every release of bootler that stamps
    format 8 also carries readers of it and a UI that can configure REproduce.
  - `UnitTemplateSource` (`core/src/product.rs:491-524`) gains the field; the
    five existing unit constants (`:728`, `:765`, `:955`, `:992`, `:1021`)
    declare none.
  - Add `reproduce` to `PACKAGE_REGISTRY`, the process paths, `SPEC_CATALOGUE`,
    `REGISTERED_MODULES` (`core/src/provisioning_file.rs:49`), and every
    five-module test list and golden (the `PACKAGED_MODULES` and
    `MANAGER_DIALLING_MODULES` constants, `product.rs:3876-3884`, and the lists
    in identity, provisioning, carrier, staging, release-tool and
    `e2e/single/assert_release_records.sh`). Tests that use `reproduce` as the
    stock unregistered package id switch to a fixture id that will never be
    registered (`not-a-package`).
  - The comment block at `versions/components.toml:613-619` ("reproduce
    deliberately absent") is rewritten.
  - `docs/modules.md` gains a REproduce section in the existing shape
    (Invocation, Configuration, Data directory, Privileges beyond the product
    account — `adm` —, Listening addresses — none —, Certificate reload,
    Compatibility) and joins the shared tables; `docs/release.md` member counts
    and the RFC 0004 sentences that call `reproduce` unpackaged or count five
    modules are updated.
- **[DECISION] Operator prerequisites, stated in bootler's release notes and
  `docs/modules.md`:** update the REview host with the new bootler release (it
  writes the `reproduce` provisioning entry REview admits packages against and
  places the bootroot safe-set entry, bootler RFC 0004 `:646-651`), and update
  roxyd on the target host, before installing REproduce.

### 4.9 Central Manager (review-database, review-web, review)

- **[DECISION] Agent kind `LogCollector`:** review-database
  `AgentKind::LogCollector = 5`, serialized `log_collector`, `package_id()` →
  `"reproduce"` (`src/tables/agent.rs:30-57`). No migration: existing records
  keep their discriminants.
- **[DECISION] review-web:** GraphQL `AgentKind` gains `LOG_COLLECTOR`
  (`src/graphql/node.rs:59-66`); `MODULE_PACKAGE_IDS` gains `reproduce`
  (`src/backend.rs:203-204`).
- **[DECISION] REview refuses a package a host cannot read.** In `install_steps`
  (after `open_build`, before `allocate_install`, review
  `src/deploy/apply.rs:797-805`) and `update_steps` (after `open_build`, before
  `begin_update`, `:891-903`), so before any ledger row exists and before the
  mutation answers — Host Agent and core-component updates included — REview
  reads the package's manifest `format_version` from the opened handle (as
  `read_generation_facts` does, `src/trust/archive.rs:648-656`) and rewinds it,
  then compares it with the `manifest_formats` range the target host last
  reported. Outside the range the operation is refused with a new
  `ApplyRefusal`, carrying the host, the package's format version and the host's
  range; review converts it to the new `DeployError::ManifestFormatUnsupported`
  in its `From<ApplyError> for DeployError` (review
  `src/deploy/deployer/apply_error.rs:20-65`, where every refusal falls to
  `DeployError::Other` today). A package with no `format_version` (a
  pre-versioned baseline) and a host that has not reported a range are not
  checked; roxyd still refuses by version (`src/deploy/outcome.rs:199-203`).
  This follows the existing per-host trust-delivery check
  (`src/trust/delivery.rs:385-392`). Recovery sends (`send_install`) are not
  re-checked.
- **[DECISION] review-web** exposes `DeployError::ManifestFormatUnsupported {
  host, formatVersion, min, max }` and adds it as a member of the
  `InstallServiceResult`, `UpdateServiceResult` and `UpdateCoreComponentResult`
  unions (review-web `src/graphql/node/deploy.rs:238-243`, `:353-377`).
- **[DECISION] review:** `reproduce` joins `PACKAGE_REGISTRY`
  (`src/store/identifier.rs:15-38`, dropping the "deliberately unpackaged"
  sentence) and `MODULE_PACKAGE_IDS` (`:50-51`), `HOST_INGEST_PACKAGE_IDS`
  (`src/admin/ingest.rs:23-35`), `AGENT_KINDS` (`src/deploy/installed.rs:36-41`)
  and the listeners match (`src/deploy/listeners.rs:58-66`) as a module that
  binds no address. No per-name push like Hog's or Crusher's
  (`src/agent.rs:1043-1514`) is needed; `get_config` and `update_config` already
  work for any agent key.

### 4.10 Clumit Security Web (aice-web-next)

- **[DECISION] A Log Collector service.** Registry kind `log-collector`, agent
  kind `LOG_COLLECTOR`, package id `reproduce`, column key `logCollector`, UI
  label "Log Collector" (ko: "로그 수집기"). It joins every hard-coded list:
  `src/lib/node/service-registry.ts:97-102`, `:123-138`, `:304-347`;
  `src/lib/node/types.ts:36-40`; `src/lib/node/install-state-decode.ts:231-236`;
  `src/components/node/node-edit-dialog-state.ts:48-61`
  (`PREFIX_BY_REGISTRY_KIND`, `AGENT_KIND_BY_REGISTRY_KIND`);
  `src/components/node/node-edit-dialog-schema.ts:33-38` (`SERVICE_SCHEMAS`:
  `"log-collector": logCollectorFormSchema`; a missing entry silently skips
  validation); the render switch in
  `src/components/node/node-edit-dialog.tsx:1563-1576` (a `log-collector` branch
  passing `dataStoreOptions`; the fallback renders the form without them);
  `src/lib/node/service-status.ts:59-95` and `AWAITS_CONFIGURATION`
  (`:273-277`); `src/components/node/node-list-types.ts:47-58`,
  `SERVICE_COLUMN_ORDER` (`:65-71`) and `emptyServiceCells` (`:79-85`);
  `src/components/node/node-detail-service-grid.tsx:130-157`;
  `src/lib/node/conflict-patterns.ts:177-183`;
  `src/lib/node/module-observation-contract.ts:35-50`, `:177-198`;
  `src/lib/node/module-observation-state.ts:34-46`;
  `src/lib/node/module-observation.ts:233-258`; i18n `nodes.serviceLabels` and
  the form's own field, hint and validation-message keys in `en.json` and
  `ko.json`. The vendored `schemas/review.graphql` is refreshed from the
  review-web release with `LOG_COLLECTOR`.
- **[DECISION] Form-only, like Piglet, Hog and Crusher.** A new instance starts
  `config: null, draft: ""` and shows Awaiting configuration
  (`decisions/node-field-catalog.md:89-95`). New files:
  `src/lib/node/services/log-collector.ts` exporting `{defaults, serialise,
  deserialise}` (`src/lib/node/services/types.ts:108-112`) and
  `src/components/node/forms/log-collector-form.tsx`.
- **[DECISION] Fields.**
  - Data Store: the existing picker (`decisions/node-field-catalog.md:434-466`)
    sets `giganto_name` and prefills the receive listener port from the picked
    Data Store, as for Piglet; Data Store IP and port form
    `giganto_ingest_srv_addr` exactly as Piglet's
    (`src/lib/node/services/sensor.ts:381-384`).
  - Collectors: a table of 1 to 64 rows; each row has Kind (text), File path
    (text) and Start (New lines only — default — / Include existing content).
    Rows can be added and removed.
  - Nothing else is emitted: no `log_path`, `report`, Elastic, import or
    transfer-count key.
- **[DECISION] Validation at save.** Kind matches §4.2's pattern; path follows
  §4.2's path rules; 1 to 64 collectors; kind and path are each unique across
  every collector of every Log Collector agent on the node, comparing this
  agent's draft with the other agents' drafts and applied configurations.
  Messages name the conflicting agent.
- **[DECISION] Serialisation** emits §4.2's keys in the order shown there, one
  `[[collectors]]` table per row with `start` always written.
- **[DECISION] Format refusal message.** The module install and update flows and
  the core-component update flow (`src/lib/node/core-update.ts`,
  `src/app/api/nodes/core-components/update/route.ts`) show
  `ManifestFormatUnsupported` (§4.9) with its host and versions (en and ko):
  - package newer than the host reads (`v > max`), any target but the Host
    Agent: "The Host Agent on {host} reads package formats {min}–{max}; this
    package is format {v}. Update the Host Agent first.";
  - the same for the Host Agent itself (a host that missed a readers release,
    §4.8): "The Host Agent on {host} reads package formats {min}–{max} and
    cannot read this update (format {v}). Upload the Host Agent package of the
    release that added readers for format {v}, update to it, then update again."
    This applies to format changes that shipped a readers release; under this
    RFC's one-step change no deployed host can reach it (§4.8);
  - package older than the host reads (`v < min`): "This package is format {v},
    older than the Host Agent on {host} accepts ({min}–{max}). Choose a newer
    build."
- **[DECISION] Log-kind helper for the Unsupervised Engine.**
  `collectLogKinds(nodes)` returns `{ kind, sensors }[]` sorted by kind, built
  from the *applied* `config` of every `LOG_COLLECTOR` agent (not drafts) on
  nodes with an applied `profile.hostname`, where each sensor is
  `reproduce.<profile.hostname>` and sensors are de-duplicated. It reads through
  the existing `listAllNodes` path (`src/lib/node/server-actions.ts:454-473`)
  and so sees only the caller's customers; it follows the `collectSensorNodes`
  precedent (`src/lib/node/sensor-list.ts:46-60`). An agent whose applied config
  does not parse is skipped. The training form that consumes it is out of scope
  (§3).
- **[DECISION] Documentation.** `decisions/node-field-catalog.md` gains a Log
  Collector section; the operator manual explains that log files must exist on
  the node, that the module reads them as `clumit-security` with group `adm` (so
  `/home` and the product's own directories are unreadable), that the producer
  or logrotate keeps their size bounded, that `PrivateTmp` hides the host's
  `/tmp` and `/var/tmp`, that each node's kinds must be unique, and the
  prerequisites of §4.8.

### 4.11 Compatibility

- Giganto: unchanged ingest protocol version `0.28.0`, accepted by Giganto
  0.31.0 (§2.1).
- REview: the manager handshake uses review-protocol's protocol version
  (`0.49.0`), accepted by REview 0.61.0. Installing REproduce needs the REview
  release with §4.9 and a REview host updated by the bootler release of §4.8.
- roxyd and REview: both must be built with the deploy-core of §4.8 before any
  package of that bootler release, REproduce included, can be uploaded or
  installed. REview's format check (§4.9) turns a skipped Host Agent update into
  a refusal that names what to update.
- Local mode: no behaviour change; existing configuration files and checkpoint
  files keep working.

### 4.12 Coordination with aice-web-next RFC 0006

aice-web-next RFC 0006 (Unsupervised Engine configuration, training and models)
changes the same repositories except this one, including deploy-core (its C1
retires the `reconverge` configuration template) and bootler (its B1 moves the
engine's unit and the module pins).

- **[DECISION] Separate PRs, coordinated releases.** Neither RFC's issues
  implement the other's items. The coordination is a human release step:
  - deploy-core: if aice-web-next RFC 0006's C1 is merged but not yet released
    when §8 item 7 is merged, one deploy-core release carries both, so roxyd and
    review adopt deploy-core once.
  - bootler: §8 item 13 and RFC 0006's B1 stay separate PRs merged in whichever
    order their dependencies allow. Both move the `roxyd`, `review` and
    `aice-web-next` pins; whichever merges second pins a release (for
    aice-web-next, a commit) that contains both RFCs' required items, never one
    older than the first PR's pin. If both are open with their dependencies
    released, the human publishes the Security E2E asset once, for the head
    merged last, after rebasing it on the first.
  - Both RFCs refuse log kinds Giganto parses as named kinds (§4.2), so
    `collectLogKinds` never offers a kind RFC 0006's training refuses.
- In every other shared repository the two RFCs' changes are independent; merges
  are serialized per repository.

## 5. Edge cases

- A file rotated twice between two checks: the collector drains the handle it
  holds and then reads the current `path`; the file in between is never read.
  The collector cannot tell this from a single rotation, so the loss is accepted
  and not reported.
- Copy-truncate: lines appended between the collector's last read (up to 3 s
  earlier) and the truncation exist only in the copy, which the collector cannot
  find by inode; they are lost. If the file also grows past the old offset
  within one interval, the truncation itself is undetectable and the lines
  between are lost.
- Rename rotation: bytes written to the renamed file after the collector has
  switched away (more than one quiet 3 s interval after the rename) are lost.
- A file replaced in place by a shorter one with the same inode: treated as
  truncation.
- `path` is a symlink that is re-pointed: `stat` follows it, so it is a rename
  rotation; the new target passes the opening checks or is refused.
- An inode number reused by an unrelated file at restart or in the predecessor
  search: the collector resumes at a wrong offset; accepted as rare.
- A file whose last line never gets `\n`: held until the file is rotated or the
  collector stops; on a clean stop it is not sent and its offset is not saved,
  so it is sent after restart once complete.
- The clock stepping backwards: timestamps run ahead of real time (`previous +
  1`) until the clock catches up; after a restart they follow the clock again.
- Rotation while Giganto is unreachable: the collector reads nothing while its
  connection is down, so rotation checks pause; on reconnect it resumes from the
  acknowledged position, finding the predecessor by inode.
- Two Log Collector instances on one node: allowed; uniqueness is enforced
  across them by the UI (§4.10); each has its own state directory; one instance
  disconnecting marks the shared Giganto sensor disconnected until it, or the
  other, reconnects.
- The `adm` group missing on a host: the unit fails to start (status 216/GROUP)
  and systemd restarts it every 5 s; Ubuntu always has `adm`.
- REview sets the agent's configuration to null: REproduce keeps its last
  applied configuration until restart, and then stays idle.
- Giganto unreachable for a long time: collectors read nothing; files keep
  growing on disk and are read on reconnect from the acknowledged positions.

## 6. Acceptance criteria

1. `reproduce <CONFIG>` behaves exactly as 0.25.1 for every existing local
   configuration: the existing local-mode integration and behaviour tests pass;
   unit tests of the split sender move with it.
2. A remote-mode REproduce with no configuration in REview stays running and
   idle; after an Apply it starts the configured collectors without a restart.
3. With two collectors, both kinds arrive in Giganto under sensor
   `reproduce.<host>.<domain>` over one ingest connection; 64 collectors run on
   one connection.
4. Rename rotation (including writes to the renamed file within its quiet
   interval after the switch is detected), copy-truncate performed after the
   collector has read to EOF, a partial final line, and a restart after rotation
   each deliver every complete line at least once, and exactly once when no
   reconnect or crash happens (barring §5's cases).
5. Lines read in the same nanosecond are all stored (no key overwrite).
6. After a Giganto connection is cut while lines are in flight, every line
   written before the cut is in Giganto after reconnect.
7. An Apply that adds a collector does not move the other collectors' positions;
   one that removes a collector deletes its checkpoint, and one that keeps a
   kind with a new path replaces it.
8. Changing `giganto_ingest_srv_addr` from an unreachable address to a reachable
   one while running takes effect without a restart.
9. A collector whose path is missing does not stop the others; when the file
   appears it is read from its beginning.
10. A path under a refused directory is refused by the UI and by REproduce; a
    symlink into one is refused by REproduce; no byte of either reaches Giganto.
11. `SIGTERM` saves every acknowledged position; restarting resumes without
    loss.
12. bootler's REproduce package installs through Clumit Security Web → REview →
    roxyd, renders the unit of §4.8 and starts.
13. A roxyd or REview without the deploy-core change refuses the package by
    manifest format version; ones with it accept and install it.
14. REview refuses to send a package whose format version is outside a host's
    reported range, and Clumit Security Web shows the reason; a host within
    range is unaffected.
15. Clumit Security Web saves a Log Collector configuration that REproduce
    accepts, refuses an invalid or duplicate kind or path, and `collectLogKinds`
    returns the applied kinds with their sensors.

## 7. Test plan

- reproduce unit tests: CLI form detection and refusals; remote configuration
  parsing (every rule of §4.2 including path rules, refused prefixes,
  64-collector cap, unknown keys, empty string); apply-difference logic and
  coalescing; acknowledged-position bookkeeping from ACK timestamps; checkpoint
  encode/decode, atomic write, path mismatch, corrupt file; follow reader over a
  temporary directory for append, rename rotation with writes after the switch,
  copy-truncate, missing path, late-appearing path, symlink re-point and symlink
  into a refused prefix, FIFO in place of a file, partial line, 1 MiB split, 4
  MiB batch cap, resume with same inode / renamed predecessor / lost
  predecessor; strictly increasing timestamps; a remote kind that Giganto parses
  as a named kind (`dns`, `dns_event`, `timeseries`) is refused; per-connection
  `SIGHUP` reload flags; `SIGHUP` while idle triggers `get_config`; stray
  `*.json.tmp` cleanup; a restart before the first ACK keeps the start position.
- reproduce integration tests: an in-process QUIC server standing in for Giganto
  (the existing test certificates, `tests/cert.pem`) that receives two
  concurrent `Log` streams on one connection, sends ACKs, and drops the
  connection mid-stream; a mock review-protocol server that serves `get_config`,
  sends `update_config`, and changes the Giganto address (as Crusher's tests do,
  crusher `src/request.rs` tests).
- deploy-core: the render-order documentation (`src/module_spec.rs:66-80`) names
  the new line; render tests for a unit with and without `supplementary_groups`,
  with `run_as` (refused) and a duplicated group (refused); a format-8 manifest
  parses; a manifest stamped `MAX + 1` is refused by version; a manifest stamped
  7 with a non-empty group list is refused; rendering groups without a `User=`
  line is a typed refusal; the window predicate accepts `MAX == CURRENT` and
  `MAX == CURRENT + 1` and rejects `MAX == CURRENT + 2`.
- roxyd: a package declaring `Adm` installs and the rendered unit contains
  `SupplementaryGroups=adm`.
- bootler: `REPRODUCE_UNIT` golden; six-module lists; release-tool package set
  includes `reproduce.pkg`.
- review-database / review-web / review: kind round-trip, `package_id`, GraphQL
  enum, package acceptance in the store and host ingest; the format check
  refuses an above-range and a below-range package for a host that reported a
  range, passes one within range, and skips a host with no report and a package
  with no `format_version`; review converts the refusal to
  `DeployError::ManifestFormatUnsupported`, and review-web returns it as a
  member of each of the three result unions.
- aice-web-next: `log-collector.ts` serialise/deserialise round-trip; validation
  messages including path rules and cross-agent duplicates; `collectLogKinds`
  over fixtures with drafts, applied configs, unparsable configs and unapplied
  nodes; the service grid shows Log Collector with Awaiting configuration after
  install; the form receives Data Store options.
- Human checks after release (not issue work): a bind mount of a refused
  directory is refused; against Giganto 0.31.0, two collectors visible through
  `logRawEvents` for sensor `reproduce.<host>.<domain>`; on a test deployment,
  install REproduce from the UI, apply two collectors on `/var/log` files,
  rotate with logrotate, and see both kinds in Giganto and in `collectLogKinds`.

## 8. Suggested decomposition

Each item is meant to fit one PR; *Turn an RFC into issues* may refine it.
Releases between items are human steps (§3).

1. reproduce — Split `GigantoSender` into a connection owner and per-stream
   senders with single-flight reconnect (§4.4); local mode unchanged.
2. reproduce — Remote CLI and configuration: invocation forms (§4.1) and parsing
   and validation of the remote configuration including path rules (§4.2). Pure;
   no manager connection yet.
3. reproduce — Manager client: review-protocol connection, handshake values,
   idle mode, `get_config`/`update_config` with coalescing, signals (§4.3).
   Depends on 2.
4. reproduce — Collectors on one connection: apply difference, Giganto retry and
   address change (§4.3), one stream per collector (§4.4). Interim reading uses
   the existing `LogCollector` with polling, `start` ignored and no checkpoints;
   after a reconnect the interim reader continues from where it is, so lines may
   be lost until item 6. Depends on 1 and 3.
5. reproduce — Acknowledged positions (ACK-to-position queue, close ACK), the
   checkpoint store, and the apply-time checkpoint rules (removed collectors
   save nothing; sweep of other kinds' files) (§4.3, §4.6). This item defines
   the position type `(dev, ino, offset)` of §4.6; the interim reader supplies
   real byte offsets. Item 6 wires re-reading from the acknowledged position.
   Depends on 4. No REproduce release is cut between items 4 and 6.
6. reproduce — Follow reader for remote collectors (§4.5) using the checkpoint
   store; replaces the interim reader; remote-mode user documentation in
   `docs/en` and `docs/ko`. Depends on 5.
7. deploy-core — `UnitTemplate.supplementary_groups` with
   `SupplementaryGroup::Adm`, the readers-first rule and assert, manifest format
   8 (§4.8); see §4.12 for the release shared with aice-web-next RFC 0006 C1.
8. roxyd — Adopt deploy-core from 7. Depends on 7.
9. review-database — `AgentKind::LogCollector` (§4.9).
10. review-web — `LOG_COLLECTOR`, the `reproduce` module package, and the
    format-refusal error code. Depends on 9.
11. review — Accept the `reproduce` package and `LogCollector` agents, adopt
    deploy-core from 7, and refuse packages outside a host's format range
    (§4.9). Depends on 7 and 10.
12. aice-web-next — Log Collector form, `collectLogKinds` and the format refusal
    message (§4.10). Depends on 11.
13. bootler — Package REproduce (§4.8): the deploy-core bump, the REproduce
    recipe and unit, and the `roxyd`, `review` and `aice-web-next` recipe pins
    moved to the releases of 8 and 11 and the merge commit of 12, in one change;
    see §4.12 for the E2E asset publish shared with aice-web-next RFC 0006 B1;
    `docs/release.md` readers-first text (§4.8). Depends on 6, 7, 8, 11 and 12.
    Its Security E2E jobs stay red until a human publishes the Security E2E
    asset for the PR's head per bootler `docs/release.md` ("Publishing",
    `:2400-2420`; a declared spec requires a republished asset,
    `core/src/product.rs:3893-3898`): the agent finishes review rounds first and
    then stops pushing; the human publishes and re-runs the jobs.
