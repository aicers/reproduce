<!-- markdownlint-configure-file {
  "MD013": { "tables": false, "code_blocks": false }
} -->

# RFC 0002: Clumit Security operational logs in Giganto

Status: accepted (2026-10-22).

This RFC sends the operational logs of Clumit Security itself — the logs of its
modules, services and containers — to the Data Store (Giganto) and makes them
searchable in Clumit Security Web. REproduce, the log collector RFC 0001 makes a
Security module, carries them: a new remote-mode collector reads each host's
systemd journal and sends Giganto `OpLog` records. Every item marked
**[DECISION]** is settled; no design question remains open.

It replaces the withdrawn host-logging design (aicers/roxyd RFC 0003, status
withdrawn by aicers/roxyd#365; its issues under aicers/roxyd#362 were closed as
not planned). It builds on RFC 0001 (`rfcs/0001-clumit-security-module.md`) and
its issue tree under aicers/reproduce#984, including the typed checkpoints of
aicers/reproduce#982 as amended by aicers/reproduce#988.

Revisions this RFC was written against: reproduce `b18d68a` (RFC 0001 with
aicers/reproduce#988), giganto
`8c513eba` (0.31.0), giganto-client 0.28.0 (`9f973a27`), review `b98790a2`,
review-web `dbfec34c`, review-database `ab7df279`, aice-web-next `1e6be3a9`,
roxyd `4dc6d260`, bootler `b3568a67`, deploy-core `d125326f`, bootroot
`f8fc6dff`, piglet `6d33c1a0`, hog `02de5fef`, crusher `a1ca7086`,
petabi/reconverge `43f5dbcd`. Every `path:line` below is at these revisions.

## 1. Summary

1. **Carrier.** A REproduce remote-mode collector of the new type `journal`
   reads the host's system journal through `journalctl`, keeps only entries of
   Clumit Security's own units and containers (selected by fields journald sets
   itself), and sends each as one Giganto `OpLog`. Delivery is at least once,
   with the journal cursor as the acknowledged position.
2. **Everywhere, as a system instance.** REview installs one REproduce
   instance on every host with a connected Host Agent — core and module hosts
   alike. It belongs to the host, not to a node or customer (like roxyd); REview
   generates and keeps its configuration (Data Store and journal collector),
   and Web shows it in the System area. Customer log collectors stay RFC
   0001's node agents, as a separate instance.
3. **Record and identity.** No Giganto record or protocol change: `OpLog`'s
   `sensor` (set by Giganto from the client certificate) is the host,
   `service_name` is `clumit-security/<source type>/<journal name>`, `log_level`
   comes from the journal priority, `contents` is the message.
4. **Journal-native output.** Every Rust component writes priority-prefixed,
   uncoloured, single-entry lines when it runs under the journal, and loses its
   `log_path` option. Product containers log through Docker's journald driver.
5. **Retention.** Giganto gains `oplog_retention` (default 365 days), separate
   from the Data Store's `retention`.
6. **Search.** Clumit Security Web gets an Operational Logs page next to Audit
   Logs, behind a new `operational-logs:read` permission that only roles with
   `customers:access-all` may hold; it queries every Data Store and shows the
   stores that answered.

## 2. Motivation and current state

Today the only way to read a module's log is `journalctl` on its host
(roxyd RFC 0003 §2, measured on the 222 demo manager). Problems found there:
every Rust component writes ANSI colour codes and its own timestamp into the
journal and every line is stored at priority 6, so nothing can select warnings;
container logs are unbounded Docker json-file logs; and no screen in Clumit
Security Web shows any of it.

### 2.1 Component logging

- Every Rust component uses `tracing-subscriber` `fmt` with an INFO default
  (`RUST_LOG` overrides). With `log_path` set it writes a file without ANSI;
  without it, stdout with ANSI on: piglet `src/logging.rs:14-46`, hog
  `src/logging.rs:16-53`, crusher `src/logging.rs:13-47`, reconverge
  `src/logging.rs:18-55`, giganto `src/main.rs:1592-1627` (CLI `--log-path`,
  `src/settings.rs:61`), review `src/main.rs:170-221` (stdout adds line numbers;
  `log_path` `src/config.rs:74`), roxyd `src/main.rs:133-191` (`log_path`
  `src/settings.rs:419`, env `ROXYD_LOG_PATH`), bootroot-agent
  `src/bin/bootroot-agent.rs:16` (`fmt::init()`).
- No deployment sets `log_path` (Clumit Security Web emits none,
  aice-web-next `decisions/node-field-catalog.md:100-104`), so all of them log
  to the journal.
- hog (`src/settings.rs:266`) and crusher (`src/settings.rs:17`) open whatever
  `log_path` a pushed configuration names; piglet confines a remote one to
  `dump_dir` (`src/control/remote_check.rs:170-200`).
- Containers: aice-web-next's `docker-compose.yml` and its bundle transform
  (`scripts/build-compose-bundle-transform.mjs:21-33`, which keeps keys
  verbatim) set no `logging:`; bootroot's `docker-compose.deploy.yml` sets one
  only for OpenBao (`local`, 20m × 10, `:53-58`). The aice-web-next cron
  container writes one file per run into the `cron-logs` volume, which nothing
  prunes.
- On Ubuntu, `/usr/lib/tmpfiles.d/systemd.conf` gives group `adm` read access
  to `/var/log/journal` and its files. RFC 0001 §4.8 already runs REproduce's
  unit with `SupplementaryGroups=adm`.

### 2.2 Giganto

- `OpLog { sensor, service_name, log_level: Info | Warn | Error, contents }`
  (giganto-client 0.28.0 `src/ingest/log.rs:30-44`, `RawEventKind::OpLog = 12`,
  `src/lib.rs:51`).
- Ingest replaces `sensor` with the connection's certificate-derived
  `service.host.domain` (giganto `src/comm/ingest.rs:1340-1358`, identity
  `:450-452`, `src/server.rs:219-255`) and keys the record by timestamp plus a
  per-day sequence number, so equal timestamps never overwrite (`:1299-1358`).
  Ingest accepts protocol `>=0.27.0,<0.32.0` (`:76`); REproduce sends 0.28.0.
- `opLogRawEvents(filter: OpLogFilter, after, before, first, last)`
  (`src/graphql/log.rs:253-275`): only time is indexed; `sensor`,
  `serviceName` and `contents` are substring tests and `logLevel` an exact test
  over the time range (`:80-150`); a page holds at most 100 records
  (`src/graphql.rs:270`); the scan is synchronous (`:629-645`). The query reads
  the local store only — it is not routed to cluster peers, unlike
  `logRawEvents` (`log.rs:237`). The SDL is vendored in aice-web-next
  (`schemas/giganto.graphql:2442-2450`, `:2766`).
- Retention: one `retention` per Data Store, default 100 days
  (`src/settings.rs:27`); OpLog already has its own range delete
  (`src/storage.rs:1193-1214`); under disk pressure retention shortens a day
  at a time (`:1225-1300`). Customer-data deletion does not touch OpLog
  (`src/graphql/customer_deletion.rs:76-119`); this RFC accepts that:
  operational logs are the product's records, kept for `oplog_retention`
  (§4.8) even when a customer's data is deleted.
- GraphQL authenticates the client certificate only (`src/web.rs:146-150`).

### 2.3 REproduce

- Local mode's `oplog` kind parses tracing-style lines with a service name taken
  from the file name, one of `manager`, `data_store`, `sensor`,
  `semi_supervised`, `time_series_generator`, `unsupervised`, `ti_container`
  (`src/bin/reproduce/main.rs:176-185`, `:1312-1327`;
  `src/parser/operation_log.rs:21-80`). It is unchanged by this RFC.
- RFC 0001: remote mode carries `log` collectors only (§3, §4.2); one Giganto
  block per instance (§4.2); collectors share one connection, one stream each
  (§4.4, aicers/reproduce#981); acknowledged positions and typed checkpoints,
  log records under `<state-dir>/checkpoints/log/`, the rest of `checkpoints/`
  left to later types, startup sweep of `*.json.tmp` in `checkpoints/` and its
  subdirectories (§4.6, aicers/reproduce#982 as amended by
  aicers/reproduce#988); sensor `reproduce.<host>.<domain>` (§4.7); package
  `ModuleHosts`, `SupplementaryGroups=adm` (§4.8).

### 2.4 Placement and names

- deploy-core's `check_placement` refuses a `ModuleHosts` artifact only on a
  host whose `carries_modules` fact is false (`src/render.rs:282-312`); bootler
  sets that fact for every deployment host (`core/src/update.rs:519-537`), and
  roxyd's and REview's module install paths do not call it. A `ModuleHosts`
  REproduce therefore installs on a core host as it is.
- Unit names (bootler): modules `clumit-security-<package>-<NNN>.service`;
  `clumit-security-review.service` (`core/src/review.rs:1016`);
  `clumit-security-roxyd.service` (`core/src/update.rs:1452-1454`);
  `clumit-security-roxyd-activate.service` (`core/src/roxyd.rs:1502`);
  bootroot-agent `clumit-security-agent-<service>.service`
  (`core/src/agent.rs:101`); `clumit-security-aice-web-next-up.service`
  (`core/src/webnext.rs:82`); `clumit-security-bootroot-up.service`
  (`core/src/bootroot.rs:164`); `bootroot-registrar.service`
  (`core/src/registrar.rs:315`); `roxyd-selfupdate-boot.service`,
  `roxyd-selfupdate-crash.service` (deploy-core `src/roxyd_selfupdate.rs:100`,
  `:103`).
- Container names: compose project `aice-web-next`
  (`core/src/webnext.rs:45`, `:51`), so `aice-web-next-<service>-<n>`;
  bootroot's `container_name: ${BOOTROOT_INSTANCE:-bootroot}-<suffix>`
  (bootroot `docker-compose.deploy.yml:28`, `:68`, `:81`, `:124`) with
  bootler always passing `--instance-name <namespace>`, so
  `clumit-security-openbao`, `clumit-security-postgres`, `clumit-security-ca`,
  `clumit-security-http01` (bootler `core/src/bootroot.rs:829-838`; a
  co-located Clumit Insight uses `clumit-insight-*`).
- SANs `<instance>.<service>.<host>.<domain>` (bootler
  `core/src/identity.rs:8-11`, `:103-150`) exist for review, aice-web-next
  (`core/src/product.rs:2224-2237`), roxyd (`:2252-2257`) and every module; not
  for the side containers of aice-web-next, bootroot's containers,
  bootroot-agent, the registrar or roxyd's helper units.

### 2.5 Clumit Security Web

- Data Store reads go straight to Giganto over mTLS
  (`src/lib/graphql/external-client.ts:10-25`); a read asks every installed
  Data Store in parallel and merges by cursor, and fails as a whole if any
  store fails (`src/lib/data-store/endpoints.ts:58-106`,
  `src/lib/event/server-actions.ts:203-245`, `src/lib/data-store/merge.ts`).
- Customer scope is Web's job because Giganto checks only the certificate
  (`src/lib/data-store/scope.ts:9-21`). Roles and defaults:
  `decisions/account-management.md:29-50`, `:83-98`; permission catalog
  `src/lib/auth/permission-defs.ts:10-41`; Security-Monitor-equivalent set
  `src/lib/auth/account-role-policy.ts:53-63`.
- Audit Logs: System-group menu (`src/components/layout/sidebar-nav.tsx:54-57`,
  gate `src/lib/nav/system-nav-access.ts:56-64`, permission `audit-logs:read`);
  aice-web-next is the only audit producer and names "file → REproduce →
  Giganto" for runtime logs without building it (`decisions/audit-log.md:26`,
  `:30-41`).

## 3. Scope

In scope: everything in §4 across aicers/reproduce, aicers/giganto,
aicers/review-database, aicers/review-web, aicers/review, aicers/aice-web-next,
aicers/bootroot, aicers/bootler, aicers/piglet, aicers/hog, aicers/crusher,
petabi/reconverge and aicers/roxyd.

Not in scope:

- Any change to RFC 0001 beyond what aicers/reproduce#988 already made, to
  REproduce local mode, or to the `log` collector.
- A Giganto record, index or protocol change other than `oplog_retention`.
- Host journald configuration (retention, size, sealing, syslog forwarding):
  OS defaults stay (§4.11).
- Log level control; components keep INFO with `RUST_LOG` honoured.
- Hosts roxyd does not manage; Clumit Insight hosts and aimer-web.
- Migrating existing json-file container logs.
- Releases, tags and deployment checks (human steps). "Depends on N" in §8
  means on N's published release tag; for aice-web-next, which bootler pins by
  commit, on N's merge commit.

## 4. Design

### 4.1 Journal collector configuration

- **[DECISION] Schema.** RFC 0001 §4.2's `collectors.type` gains `"journal"`:

  ```toml
  [[collectors]]
  type = "journal"
  ```

  A journal collector has no other key; any other key is refused (RFC 0001's
  unknown-key rule). At most one journal collector per configuration. It
  counts toward the 1–64 collector limit. A configuration without one is
  valid for REproduce. Only the system instance's configuration, which REview
  generates (§4.9), contains one; the Log Collector form of RFC 0001 never
  emits it.
- **[DECISION] Identity.** The journal collector is identified by its type; an
  apply that keeps it does not restart it.
- **[DECISION] Kind rules are unchanged.** `kind` and `path` remain `log`-only
  keys; a `log` collector may still use the kind `journal`, which cannot clash
  with the journal collector's checkpoint (§4.4).

### 4.2 Reading the journal

- **[DECISION] Reader.** The collector runs `/usr/bin/journalctl` in two
  phases and reads one JSON object per line from its stdout:
  1. *Catch-up:* `journalctl --output=json --all --no-pager` with
     `--after-cursor=<cursor>` when it has a checkpoint (from the oldest entry
     when it has none), without `--follow`, until it exits. Without `--follow`
     journalctl reads every boot; with `--follow` it reads only the current
     boot (observed on systemd 259: `--follow --after-cursor` jumps to the
     current boot's first entry), which would skip a previous boot's tail.
  2. *Follow:* `journalctl --output=json --all --no-pager --follow --lines=all
     --after-cursor=<cursor of the last entry read>`; that entry is in the
     current boot once catch-up has reached the end. With no entry read in
     catch-up (empty journal) it runs `--follow --lines=all` alone.

  `--all` is required: without it the JSON output replaces any field longer than
  4096 bytes with `null`. `--output-fields` limits output to `MESSAGE`,
  `PRIORITY`, `_SYSTEMD_UNIT`, `_PID`, `UNIT`, `CONTAINER_NAME`; journalctl
  always adds `__CURSOR`, `__REALTIME_TIMESTAMP`, `__SEQNUM` and `__SEQNUM_ID`
  (exported in JSON since systemd 254; Ubuntu 24.04 ships 255), and also
  `_BOOT_ID` and `__MONOTONIC_TIMESTAMP`, which are ignored. journalctl reads
  its default merged view (no `--system`/`--user`): the sequence-number check of
  §4.3 needs every entry, and the `adm` ACL covers user journals too. No
  libsystemd is linked; the collector is built on Linux only and REproduce's
  other targets are unaffected. An output line longer than 1 MiB is skipped
  (neither parsed nor sent, its bytes not held) with a rate-limited warning,
  because any local user can write large entries to the journal.
- **[DECISION] Access check.** At start the collector validates the machine
  ID (from `/etc/machine-id`), lists `/var/log/journal/<machine-id>/`, and
  opens `system.journal` in it read-only, or, when that file is absent, an
  existing `system@*.journal` archive. Listing the directory alone is not
  enough: it is mode 2755, readable by everyone, while `system.journal` is
  0640 with read access for `adm` through its ACL (systemd
  `tmpfiles.d/systemd.conf.in:42-53`). With no system journal file yet, the
  check fails and is retried. If it fails, the collector logs an error ("cannot
  read the system journal; is the unit in group adm?") at most every 10
  minutes and keeps retrying; journalctl does not run until it passes.
  `--output=json` implies journalctl's quiet mode, which suppresses its own
  "not seeing messages" notice (systemd v255 `src/journal/journalctl.c:606-607`,
  `:2301`), so this file check supplies the missing-permission diagnostic.
  journalctl's stderr is still read and logged at warning, at most one line
  per second.
- **[DECISION] Process supervision.** journalctl runs only while the
  collector's stream is open. When the Giganto connection or the stream drops,
  the collector stops journalctl; when it reopens, it rewinds to its
  acknowledged position (RFC 0001 §4.6) and starts again with catch-up from
  that cursor. If journalctl exits during follow, or its output cannot be
  parsed, the collector logs a warning, waits 5 s and does the same.
- **[DECISION] Selection by trusted fields only.** An entry is kept when one of
  these holds, and dropped otherwise:

  | Source type | Condition | Name |
  | --- | --- | --- |
  | `unit` | `_SYSTEMD_UNIT` matches `clumit-security-*.service`, or equals `bootroot-registrar.service`, `roxyd-selfupdate-boot.service`, `roxyd-selfupdate-crash.service` or `roxyd-selfupdate-deadline.service` (deploy-core `src/roxyd_selfupdate.rs:100-105`) | `_SYSTEMD_UNIT` |
  | `systemd` | `_PID` is `1` and `UNIT` meets the `unit` condition | `UNIT` |
  | `container` | `_SYSTEMD_UNIT` is `docker.service` and `CONTAINER_NAME` starts with `aice-web-next-` or `clumit-security-` | `CONTAINER_NAME` |

  Underscore fields are set by journald and cannot be written by a client;
  `CONTAINER_NAME` alone can (the journal socket is world-writable), which is
  why the container row also requires `_SYSTEMD_UNIT=docker.service`. The
  match is exact string comparison except the one `*` wildcard, which matches
  one or more characters from `[a-z0-9@-]`, so the roxyd supervisor self-test
  instances `clumit-security-roxyd-supervisor-selftest@<nonce>.service`
  (deploy-core `src/roxyd_selfupdate_contract.rs:85-90`, lowercase hex nonce)
  are included. In journalctl's JSON a value that is an array of numbers is
  binary data (decoded as lossy UTF-8); an array of strings or of number
  arrays is a field set more than once, read by its first element.
- **[DECISION] Mapping to `OpLog`.**

  | `OpLog` / stream field | Value |
  | --- | --- |
  | event timestamp | `__REALTIME_TIMESTAMP` (µs) × 1000 + k, in ns (below) |
  | `service_name` | `clumit-security/<source type>/<name>` from the table above |
  | `log_level` | `PRIORITY` 0–3 → `Error`, 4 → `Warn`; 5–7, missing or not an integer 0–7 → `Info` |
  | `contents` | `MESSAGE` (binary or multi-valued as above); a missing one is empty |
  | `sensor` | left empty; Giganto sets it (§2.2) |

  `contents` is sent as written: escapes a component wrote (§4.6) are not
  undone. A `MESSAGE` longer than 64 KiB is cut at a UTF-8 boundary and ends
  with a space and `…[truncated]`.
- **[DECISION] Timestamps unique and increasing per stream.** RFC 0001's
  acknowledgement queue (aicers/reproduce#982) matches an ACK to a written
  entry by timestamp equality in queue order, and Giganto repeats its last ACK
  every 60 s (giganto `src/comm/ingest.rs:1260-1273`). Journal times can repeat
  within a microsecond or step back (clock change). With `u` the entry's
  `__REALTIME_TIMESTAMP` (µs), `u'` the previous kept entry's, and `p` the
  previous stamp sent on the stream (ns):
  - if `u > u'` (or the stream has no previous entry): stamp `max(u × 1000, p +
    1)`;
  - if `u = u'`: stamp `p + 1` (entries sharing a microsecond are spread by
    nanoseconds, however many there are);
  - if `u < u'`: the clock stepped back. The collector holds the entry, closes
    the stream with RFC 0001's close marker and waits for the close ACK
    (journalctl keeps running; read entries queue behind the held one); on
    the close ACK it opens a new stream and sends the held entry with stamp
    `u × 1000`. If no close ACK arrives within `CHANNEL_CLOSE_TIMEOUT`
    (15 s), it handles it as a dropped stream (process supervision, below:
    stop journalctl, rewind to the acknowledged position, catch up), because
    #982 then keeps only the last data acknowledgement.

  Stamps are thus strictly increasing within each stream, and event times are
  kept except for the nanosecond spreading of entries that share a
  microsecond.
- **[DECISION] Streams and limits.** The collector opens one `OpLog` stream on
  the instance's Giganto connection (RFC 0001 §4.4) and batches as `log`
  collectors do (≤ 1000 records or 4 MiB per batch).
- **[DECISION] Own output.** REproduce's own unit is a `clumit-security-*`
  unit, so its own lines are collected too. Its per-acknowledgement `ACK: …`
  line (`src/sender.rs:775`) moves to DEBUG in remote mode, because Giganto
  repeats ACKs every 60 s per stream and the line would otherwise add about
  1,440 records a day per stream; the `Finish ACK` line (`:773`) stays INFO.

### 4.3 Start, resume and loss

- **[DECISION] First start.** With no checkpoint the collector starts at the
  oldest entry the journal holds, so logs from before installation arrive with
  their own times. This differs from `log` collectors' default `start = "end"`
  because journal timestamps are event times.
- **[DECISION] Resume.** With a checkpoint it starts after the saved cursor.
- **[DECISION] Lost interval.** The checkpoint also stores the saved entry's
  `__SEQNUM_ID`, `__SEQNUM` and `__REALTIME_TIMESTAMP`. The collector compares
  every parsed entry with its predecessor, in catch-up and in follow, before
  the source filter. The predecessor of the first entry after a start cursor
  (start-up with a checkpoint, rewind after a reconnect or a missing close ACK,
  journalctl restart, and the saved tail after a corrupt checkpoint) is
  that start position; after that it is the entry parsed before, kept or
  dropped. A follow process held back by a slow sink keeps running across a
  rotation or vacuum and continues with the entries that survive (systemd v255
  `src/journal/journalctl.c:2100`, `:2578`), so a check made only when catch-up
  starts would miss that gap. If an entry has the same `__SEQNUM_ID` as its
  predecessor and a `__SEQNUM` greater than the predecessor's plus one plus
  the number of over-long lines (§4.2) skipped between them, or a different
  `__SEQNUM_ID`, the collector logs one warning naming the two entries' times
  ("journal entries between … and … may be missing: removed before they were
  sent, or lost by journald"). Sequence numbers count every entry, kept or
  not, so filtering does not cause false warnings; an unclean shutdown can
  leave a real gap, which is why the wording says "may". The warning reaches
  Giganto through the journal like any REproduce line. The collector keeps the
  cursor pair of its last warning in memory and does not warn again for the
  same pair, so a rewind that replays the gap does not repeat it. A comparison
  where either side lacks sequence numbers is skipped, with one informational
  line per continuous run of skipped comparisons.
- **[DECISION] Corrupt checkpoint.** Following RFC 0001 §4.6's load order, a
  corrupt journal checkpoint (unreadable, unparsable, or `type` other than
  `"journal"`) loads as the journal's current tail: the collector reads the
  newest entry (`journalctl --output=json --all --lines=1 --no-pager`), saves
  its cursor at once, logs a warning that unsent earlier entries may be skipped,
  and starts the follow phase after that cursor.

### 4.4 Checkpoint

- **[DECISION] File.** `<state-dir>/checkpoints/journal.json`, outside
  `checkpoints/log/` as aicers/reproduce#988 reserves, holding `{"type":
  "journal", "cursor": …, "seqnum_id": …, "seqnum": …, "realtime_us": …}`. The
  temporary file is `journal.json.tmp`, so RFC 0001's startup sweep covers it.
  Writing cadence, `fsync` and rename follow RFC 0001 §4.6.
- **[DECISION] Position.** Each batch carries, as its position, the cursor of
  the last entry read up to and including its last record, with that entry's
  `__SEQNUM_ID`, `__SEQNUM` and `__REALTIME_TIMESTAMP`. When every written
  batch is acknowledged and the reader holds no unsent record, the
  acknowledged position is that of the last entry read, so entries the filter
  drops after the last kept one do not hold the position back.
- **[DECISION] Removal.** A configuration without a journal collector leaves
  `journal.json` in place; RFC 0001's apply-time deletion touches only
  `checkpoints/log/`.

### 4.5 REproduce release

- **[DECISION]** The journal collector ships in a REproduce release that also
  contains RFC 0001's remote mode; it needs RFC 0001's sender split, shared
  connection and typed checkpoints (aicers/reproduce#978, #981, #982).

### 4.6 Component output under the journal

- **[DECISION] Journal detection.** A component treats its output as the journal
  when `JOURNAL_STREAM` is set and its `<dev>:<ino>` equals the `st_dev:st_ino`
  of file descriptor 1 or 2.
- **[DECISION] Format under the journal.** Each event is written as one line:
  `<N>` (syslog priority: ERROR 3, WARN 4, INFO 6, DEBUG and TRACE 7), then the
  `fmt` output without timestamp and without ANSI, with every line break inside
  the event written as `\n` and every NUL as `\0` (other characters,
  backslashes included, are written as they are).
  systemd stores the prefix as `PRIORITY` (`SyslogLevelPrefix=` default yes).
  Both stdout and stderr lines carry the prefix.
- **[DECISION] Panics.** Under the journal a panic hook replaces the default
  one: it logs the panic message, location and thread name at ERROR through
  `tracing` (one entry) and nothing else. Elsewhere the default hook stays.
- **[DECISION] Elsewhere** (a terminal, a pipe, a file): output is today's,
  with ANSI only when the stream is a terminal.
- **[DECISION] `log_path` is removed** from piglet (including
  `resolve_log_path`), hog, crusher, reconverge, giganto (`--log-path`), review
  and roxyd (`log_path`, `ROXYD_LOG_PATH`). A configuration file or pushed
  configuration that names `log_path`, or a command line with `--log-path`,
  is refused with a message saying the option was removed and logs go to
  standard output. Level stays INFO by default, `RUST_LOG` still overrides.
- **[DECISION] Components.** piglet, hog, crusher, petabi/reconverge, giganto,
  review, roxyd, reproduce (remote and local mode, since the output rule is
  about the stream, not the mode; local mode keeps its `log_path`) and
  bootroot-agent (output only; it has no `log_path`).

### 4.7 Containers

- **[DECISION]** The aice-web-next product bundle transform
  (`scripts/build-compose-bundle-transform.mjs`) adds
  `logging: { driver: journald }` to every service it keeps; bootroot's
  `docker-compose.deploy.yml` sets the same for every service of the
  production stack, replacing OpenBao's `local` driver. Development compose
  files are unchanged (Docker Desktop has no journald). Docker records stdout
  as priority 6 and stderr as 3, which §4.2 maps to Info and Error.
- **[DECISION] cron.** The cron container writes each run's result to stdout
  as one line, cut to 2 KiB, instead of a file; the `cron-logs` volume is
  removed from the compose file and the bundle.

### 4.8 Giganto retention

- **[DECISION] Setting.** `ConfigVisible` gains `oplog_retention: Duration`
  (`humantime_serde`, `#[serde(default)]` = 365 days, so a configuration or an
  `updateConfig` argument without the key still parses; giganto
  `src/settings.rs:27`, `:132-133`, `:312-313`), written by
  `update_config_file` (`:224-246`). `ConfigVisible::validate` (`:291-296`)
  refuses a value below one day. The GraphQL `config` query returns it as
  rounded-up days like `retention` (`src/graphql/status.rs:54-63`, `:129-132`)
  and `updateConfig` accepts it (`:152-212`); a change restarts Giganto as a
  `retention` change does (`src/main.rs:1349-1351`).
- **[DECISION] Deletion.** The retention task (`src/main.rs:778`, `:796`,
  `:1524-1544`; `src/storage.rs:1416-1462`) computes a second cutoff from
  `oplog_retention` and the OpLog range delete (`src/storage.rs:1193-1212`)
  uses it; every other column family keeps `retention`. Under disk pressure
  (`:1247-1280`) both cutoffs move forward by the same day steps.

### 4.9 Central Manager (REview): the system instance

Today every module instance REview knows is a row of a node — `Agent` or
`ExternalService` inside `Node`, written by `record_install` on success, which
finds the node by `profile.hostname` (review `src/deploy/installed.rs:1-19`,
`:327-398`, `:738-750`); a node is a customer's host (`Profile.customer_id`,
review-database `src/tables/node.rs:775-780`), and core components deliberately
have none (aice-web-next `src/lib/node/core-update-contract.ts:11-13`). The
operational-log collector must run on core-only hosts too, so it is not a node
agent: it is a **system instance**, one per host, owned by REview. RFC 0001's
aicers/review#2369 makes `reproduce` a known package (`PACKAGE_REGISTRY`,
`MODULE_PACKAGE_IDS`, `HOST_INGEST_PACKAGE_IDS`, `review
src/store/identifier.rs`, `src/admin/ingest.rs:23-35`); this RFC builds on it.

- **[DECISION] Record.** review-database gains a table of system instances keyed
  by host — the SAN without its first two labels, i.e. the `host.domain` part
  review's `agent_info_from_san` / `split_agent_lookup_key` yield (review
  `src/tls/certificate.rs:60-68`, `:71-73`; the form `profile.hostname` uses,
  domain labels included): `{ host, instance: Option<u32>, install_keys:
  Vec<UUID>, installed_version, installed_commit, data_store: Option<server
  name>, config: Option<String>, last_refusal: Option<{ at, message }> }`.
  `install_keys` lists every request key REview has used for this host's
  system installs, newest last; a key is dropped when the ledger prunes its
  attempt. It has no customer and no node.
- **[DECISION] Reconcile triggers.** REview reconciles a host when its roxyd
  connects, when a system install of that host finishes successfully (the
  finalizer triggers it, as `Finalizer.core_components` does for core
  components, review `src/deploy/outcome.rs:314-321`), when the maintenance
  gate releases (a `GateHook::on_release`, `src/maintenance/gate.rs:40-51`, as
  the core-component reconcile does), when the operator changes its Data
  Store, and for every connected roxyd host (`roxyd_hosts()`,
  `src/agent.rs:720-733`) every 10 minutes. All triggers go through one
  pending-host set, at most one reconcile per host at a time (as
  `src/deploy/core_components.rs:29-34`).
- **[DECISION] Install step.** The row's newest key's attempt is read from the
  ledger (`operation_attempt_map().get`):

  | State | Action |
  | --- | --- |
  | no row | create the row with a fresh key and install |
  | row with no instance, newest attempt not finalized | wait |
  | row with no instance, newest attempt `Succeeded` | copy its instance and build into the row (repairs a row write that failed) |
  | row with no instance, newest attempt `Failed`, `RolledBack` or `Cancelled`, finalized ≥ 1 h ago | new key, install |
  | row with no instance, no attempt under the newest key (refused before a ledger row, or a crash before admission) | install with a new key, unless `last_refusal` is less than 1 h old |
  | row with an instance | nothing (configure step) |

  Installing means: take the first build review's `servable_builds` returns
  for `reproduce` (newest accepted, withdrawn excluded; review
  `src/deploy/apply.rs:1240-1252`) — on `VerificationPending` or another read
  error skip this round without recording a refusal; append a fresh UUID v4
  key to `install_keys` under the store lock (review-database
  `src/tables/operation_attempt.rs:1264-1268` refuses any other form); call
  `RoxydDeployer::install` (`src/deploy/deployer.rs:92` → `install_steps`,
  `src/deploy/apply.rs:793-822`) with that key,
  `BuildSelector::Commit(<that build's commit>)`, no bind addresses, no
  configuration template, and `on_failure = Rollback` when the host reports
  `ROLLBACK_SUPERVISOR`, `Hold` otherwise (the rule of review-web
  `src/graphql/node/deploy.rs:547-568`). A refusal returned by the call
  (format unsupported, build not servable, an unnumbered legacy instance, …)
  is stored in `last_refusal`; a refusal because the maintenance gate is
  closed is not stored, since the gate's release triggers a reconcile. The
  instance number is allocated per `(host, reproduce)` as for any module
  (`operation_attempt.rs:1603`), so it never collides with a node Log
  Collector on the same host. REview logs one INFO line naming host, build
  and key.
- **[DECISION] Configure step.** For a row with an instance, REview chooses the
  Data Store: the row's `data_store` if that store is still installed;
  otherwise (none chosen yet, or the chosen store was removed) the first, by
  server name, installed store that has an address and an allocated ingest
  port, which it then **persists** in `data_store` (logging a warning when it
  replaced a removed one). A store that is installed but momentarily
  unresolvable is kept, not replaced. It renders the configuration below, and
  when the text differs from `config` it stores it and sends `update_config`
  (review `src/agent.rs:1407-1427`, which finds the connection by key and
  needs no node). With no usable store, `config` stays as it is (`None` on a
  new row, so the instance waits, RFC 0001 §4.3).
- **[DECISION] Data Store addresses.** "Installed" means a Giganto service row
  with an installed version whose lifecycle is neither not-installed nor
  removing — the filter review-web's `dataStoreEndpoints` applies
  (`src/graphql/node/data_store_endpoint.rs:40-89`). `giganto_name` is the
  store's server name (`<instance:03>.giganto.<host>`) and its addresses are
  those review's Giganto config plane resolves (`read_endpoint`, review
  `src/agent.rs:1431-1444`, `src/deploy/giganto.rs:567-580`);
  `giganto_ingest_srv_addr` is the first of them with the port allocated to
  the store's `ingest_srv_addr` (`port_allocation_map().allocated_for`,
  `src/deploy/giganto.rs:531-566`).
- **[DECISION] Configuration.** REview renders:

  ```toml
  giganto_ingest_srv_addr = "<ip>:<receive port>"
  giganto_name = "<server name>"

  [[collectors]]
  type = "journal"
  ```

  Nobody edits it by hand.
- **[DECISION] Outcome recording.** `write_row` (review
  `src/deploy/outcome.rs:622-680`), which runs on terminal success, sets the
  row's `instance` and build when the attempt's idempotency key is in a row's
  `install_keys`, instead of calling `record_install`; and updates the row's
  build when the success is an update of a `(host, reproduce, instance)` a row
  holds, instead of `record_status`. Failures need no recording: the install
  step reads them from the ledger (both the finalizer's failure path,
  `outcome.rs:607-620`, and the ledger sweep, `src/deploy/ledger_sweep.rs:1-14`,
  end attempts there). Node Log Collector installs and updates are unchanged.
- **[DECISION] Keeping node paths off the system instance.**
  - The `update` and `remove` adapters of `RoxydDeployer` (review
    `src/deploy/deployer/update.rs:36-56`, `deployer/remove.rs`), which
    `updateService` and `removeService` reach (review-web
    `src/graphql/node/deploy.rs:793-858`), refuse a `(host, reproduce,
    instance)` that a system row holds with a new
    `DeployError::SystemInstance { host }` ("this is the host's operational
    log collector; update it from Operational log collectors"). The system
    update path calls `applier().update` directly, so it is not refused;
    nothing removes a system instance.
  - `inFlightInstalls` and `latestInstall` (review-web
    `src/graphql/operation_attempt.rs:361-410`), which node cards read
    (aice-web-next `src/lib/node/module-observation.ts:35-64`), leave out
    attempts whose key is in any row's `install_keys`, and the install step
    reads only those attempts, so operator installs of a Log Collector and
    system installs never see each other.
- **[DECISION] `get_config`.** `get_agent_config` (review
  `src/agent/requests.rs:497-522`) first looks for a row whose host and
  `<instance>.reproduce` match the peer's SAN and returns its `config`
  ("config unavailable" while `None`); otherwise it resolves through the node
  as today.
- **[DECISION] Status.** Connection state comes from the agent registry by key
  (`src/agent.rs:736-746`), which needs no node. For a system instance REview
  skips the node-based persisted status write (review `src/agent.rs:916-925`,
  "Failed to update agent status" at info, from review-database
  `src/tables/node.rs:699-730`).
- **[DECISION] Build retention and exposure.** The module store's retention
  (review `src/deploy/recorded_builds.rs:174`) and withdrawn-build exposure
  (`src/trust/exposure.rs:349-356`) also read system rows, so the build a
  system instance runs is neither pruned nor missed.
- **[DECISION] Interfaces.** review exposes to review-web, through its backend
  traits next to `PackageDeployer` (review-web `src/backend.rs:708-860`):
  `system_log_collectors()` (the rows plus `connected` and the newest attempt),
  `set_system_log_collector_data_store(host, server_name)` (refuses a server
  name that is not an installed Data Store; stores it and enqueues the host's
  reconcile) and `update_system_log_collector(host, build_selector, on_failure)`
  (`applier().update(host, "reproduce", Some(instance), …)`, refused for a row
  without an instance). review-web publishes them as GraphQL, System
  Administrator only and not under `Node` (as `coreComponentList`, review-web
  `src/graphql/core_component.rs:1-9`, `:40-51`): `systemLogCollectorList` (per
  row `host`, `instance`, `installedVersion`, `installedCommit`, `dataStore`,
  `connected`, `lastRefusal`, `latestOperationAttempt`),
  `setSystemLogCollectorDataStore(host, serverName)`, and
  `updateSystemLogCollector(host, buildSelector, onFailure)` with the same
  Rollback-capability check as `updateService`.
- **[DECISION] Lifecycle limits.** Version updates are operator actions only;
  the reconcile installs, it does not upgrade. A decommissioned host's row
  stays and shows as disconnected (accepted; no removal path in this RFC).
  If an operator removes the unit or data directory by hand, REview does not
  notice; that is out of scope.
- **[DECISION] Giganto configuration.** REview's Giganto config client adds
  `oplogRetention` to its query, its mutation's arguments and the mutation's
  selection set (review `src/deploy/giganto/client.rs:18-19`, `:300`), with
  these rules for a Giganto older than §4.8:
  - If a request fails with a GraphQL validation error naming
    `oplogRetention`, REview repeats it without the field and treats that
    store as lacking it for the rest of the process's life.
  - REview pushes a stored configuration when it differs from the live one
    (`src/deploy/giganto.rs:417-419`), and Giganto's `updateConfig` compares
    the whole `old` value (giganto `src/graphql/status.rs:174-178`). When the
    live configuration lacks `oplog_retention`, the key is left out of the
    comparison and of both `old` and `new`. When the store has it but the
    stored text lacks it, the stored text is compared as carrying the live
    value, and a push writes the live value into `new` (otherwise Giganto's
    default would reset it to 365 days).

### 4.10 Clumit Security Web (aice-web-next)

- **[DECISION] Menu.** "Operational Logs" (`/operational-logs`) in the System
  group, right after Audit Logs, shown when the user holds
  `operational-logs:read`.
- **[DECISION] Central Manager reads.** A new helper,
  `buildOperationalLogsDispatchContext` (next to
  `buildSystemAdministratorDispatchContext`,
  `src/lib/node/dispatch-context.ts:166-195`, which stays as it is and keeps
  refusing custom roles), re-checks at call time that the session holds
  `operational-logs:read` and `customers:access-all`, and returns a System
  Administrator Central Manager context. It is used only for
  `systemLogCollectorList` and `listDataStoreEndpoints` on this page, each call
  site carrying the `scope-allowlist` override with that reason (as
  `src/lib/data-store/endpoints.ts:66`). This elevation is deliberate: a custom
  role allowed by the next item has no Central Manager role of its own
  (`reviewRoleFor`, `src/lib/review/role.ts:57-60`), and operational logs are
  not customer-scoped. No other Central Manager call is made with it; in
  particular, for a session without a built-in Central Manager role the page
  shows sources as text, without the node and core-component links of the
  Display item. Tests cover the helper's refusals (missing either permission,
  built-in roles without access-all).
- **[DECISION] Permission.** `operational-logs:read` joins the catalog
  (`src/lib/auth/permission-defs.ts`). Existing built-in-role editing remains
  disabled (`src/lib/auth/role-management.ts:254-256`), so the System
  Administrator grant made by the auth migration below cannot be removed through
  the role editor in this RFC. Custom roles may add or remove the
  permission subject to the access-all invariant; the catalog does not mark it
  as one of the locked permissions (🔒 in
  `decisions/account-management.md:83-98`). Saving a role that holds it without
  `customers:access-all` is refused with a message naming the requirement; it is
  not added to the Security-Monitor-equivalent set
  (`src/lib/auth/account-role-policy.ts:53-63`). A new auth migration grants it
  to System Administrator (defaults live in
  `migrations/auth/0001_init_schema.sql:40-100`); labels in
  `src/i18n/messages/en.json` and `ko.json` (`permissionGroups`,
  `permissionLabels`), and a row in the permission table of
  `decisions/account-management.md:83-98`. The role-save refusal lives with the
  other role rules (`src/lib/auth/role-management.ts`) and also refuses removing
  `customers:access-all` from a role that keeps `operational-logs:read`. The
  page checks the permission with `requirePermissionOrForbidden`
  (`src/lib/auth/session.ts:63`) and its server actions with `hasPermission` (as
  `src/lib/event/server-actions.ts:101` does).
- **[DECISION] What counts as ours.** A record is shown only if its `sensor` is
  `reproduce.<host>` of a host in `systemLogCollectorList` and its `serviceName`
  starts with `clumit-security/unit/`, `clumit-security/systemd/` or
  `clumit-security/container/`. Records from local-mode `oplog`, from other
  deployments or from any other sender are therefore never shown.
- **[DECISION] Filters.**
  - Time range: required, at most 31 days; default the last hour.
  - Host: all, or one host of `systemLogCollectorList`.
  - Source: all, or one source of the chosen host.
  - Level: any non-empty subset of Info, Warn, Error.
  - Text: one substring, 1–256 bytes, case-sensitive.
- **[DECISION] Queries.** For each Data Store and each selected level (one
  query without `logLevel` when all three are selected), `opLogRawEvents` with
  `time`, `sensor` (`reproduce.<hostname>` for one host, `reproduce.` for all),
  `serviceName` (the full `clumit-security/<type>/<name>` for one source,
  `clumit-security/` otherwise), `contents` and `last: 100`, newest first; the
  results are merged by time, re-checked against the "ours" rule and the exact
  host and source (Giganto's tests are substrings), and shown 100 per page.
  Each (store, level) query keeps its own `before` cursor and advances only by
  the records the page consumed from it; when re-checks drop records, the
  page fetches further from the same queries until it holds 100 records, the
  queries are exhausted, or 5 fetches per query have been made (the page then
  shows what it has and offers "load more").
- **[DECISION] Timeout and partial results.** Each request is aborted after
  30 s. A store that failed or timed out is listed in a warning above the
  results ("Data Store {name} did not answer; logs stored there are missing.
  They remain in the journal of the hosts that send to it."), and the other
  stores' results are shown. The warning also names the hosts whose system
  instance's `dataStore` is that store. "Retry" queries every
  store again from the first page. A timeout suggests a narrower range.
- **[DECISION] Display.** Columns: time (the user's time zone), host, source,
  level, message. A source with a SAN is shown and linked by it — modules
  `clumit-security-<package>-<NNN>.service` → `<NNN>.<package>.<host>.<domain>`;
  `clumit-security-review.service`, `clumit-security-roxyd.service` and the
  `aice-web-next-next-app-<n>` container → that component's SAN — and links to
  its node and agent when it is a node's module, or to its row in the core
  components list when it is a core component. Other sources are shown as
  "component / name" (e.g. "aice-web-next / nginx-prod", "bootroot / openbao"
  for `clumit-security-openbao`, "roxyd / roxyd-activate"). `systemd` lines are
  marked "systemd". The mapping is display-only; stored values are never
  rewritten.
- **[DECISION] Collectors view.** The System area gets "Operational log
  collectors", next to the core components list and gated like it (System
  Administrator): one row per `systemLogCollectorList` entry with host,
  version, connection, Data Store (a picker of the installed stores; saving
  calls `setSystemLogCollectorDataStore` and writes an audit entry
  `operational_logs.set_data_store`), and an Update action using the module
  build picker and `updateSystemLogCollector` (audit
  `operational_logs.update_collector`). A row without an instance shows
  "installing", or its latest attempt's failure, or its `lastRefusal`
  message (e.g. a host that cannot read the package format).
- **[DECISION] Audit.** Every search writes an audit-log entry
  (`auditLog.record`, `src/lib/audit/logger.ts:124-142`) with a new action
  `operational_logs.search` and target type `operational_logs`
  (`src/lib/audit/schema.ts:149-171`, `:482`), registered as
  `"customer-agnostic"` in `src/lib/audit/customer-scope-policy.ts` (as
  `:155`), with the filters and the text cut to 256 bytes in its details.
- **[DECISION] Log Collector form.** Unchanged by this RFC: the form of
  aicers/aice-web-next#1239 emits `log` collectors only.
- **[DECISION] Data Store form.** Gains "Operational log retention" next to
  retention (`oplog_retention`, whole days, 1–3650, default 365), with the same
  schema and wire conversion as retention (`src/lib/node/validation.ts:237-266`,
  `src/lib/node/services/data-store.ts`,
  `src/components/node/forms/data-store-form.tsx`) and a row in
  `decisions/node-field-catalog.md:242-290`.

### 4.11 Host journal

- **[DECISION]** Host journald settings stay the OS defaults (Ubuntu:
  persistent, size limit 10 % of the file system up to 4 GiB, no time limit,
  `ForwardToSyslog=yes`). The journal is only the collector's buffer; the
  record of truth is Giganto. Logs leave the host within seconds, so a later
  compromise of the host cannot change what was sent.

## 5. Edge cases

- **No Data Store yet.** The instance waits for its first configuration (RFC
  0001 §4.3); the journal keeps the entries and the collector sends them, with
  their journal times, once configured.
- **Giganto unreachable for a long time.** The collector stays at its
  acknowledged cursor; when the journal's size limit removes entries it has not
  sent, the lost-interval warning (§4.3) records the gap.
- **Data Store changed.** An apply that changes the Giganto block moves the
  collector to the new store from its acknowledged cursor (RFC 0001 §4.3
  address change); entries already sent stay in the old store, which Web still
  queries.
- **Clock jump on the host.** Records carry the journal's realtime stamp, so a
  host clock step back shows as out-of-order times; the collector starts a new
  stream at the step (§4.2), so acknowledgements stay exact and nothing is
  dropped.
- **Journal rotation or vacuum while following.** `journalctl --follow` follows
  rotation itself; a vacuum that removes unread entries is a lost interval.
- **A reinstalled host.** A new machine ID or a wiped journal gives a new
  `__SEQNUM_ID`; the collector warns once (§4.3) and continues from the oldest
  entry after the saved realtime it finds. (A restored journal with the old
  sequence numbers is not detected as a gap.)
- **REproduce stopped.** Its own last lines stay in the journal and are sent
  when it starts again, from its checkpoint.
- **Two REproduce instances on a host.** A host that also collects customer
  logs runs the system instance and a node Log Collector instance: two Giganto
  connections under the same sensor `reproduce.<host>.<domain>`, one sending
  `OpLog`, the other `Log`. They share no checkpoint (separate state
  directories) and no kind (the journal collector has none).
- **System instance tampered with by hand.** If its unit or data directory is
  removed outside REview, REview does not notice (§4.9 lifecycle limits). If
  the data directory alone is lost, the instance starts at the oldest entry
  again and Giganto stores the retained journal a second time (OpLog keys
  never overwrite); accepted, the duplicates expire with `oplog_retention`.
- **Long events.** A container line over Docker's 16 KiB partial-message limit,
  or a unit line over journald's `LineMax` (48 KiB default), is split into
  several entries; accepted.
- **Chosen Data Store removed.** The reconcile picks and persists the first
  usable store and logs a warning; entries sent to the removed store are gone
  with it. A store that is only unreachable is kept.
- **Data Store added later.** Hosts keep the store they have; a new store that
  sorts first is used only by hosts configured after it appears.
- **Reboot between runs.** Catch-up (§4.2) reads across boots, so a previous
  boot's last lines (shutdown messages) are sent after the restart.
- **A unit or container renamed by a later bootler.** Old records keep the old
  name; only Web's display mapping (§4.10) needs the new name.
- **A message containing `clumit-security/`.** The "ours" test reads
  `serviceName`, not `contents`.
- **A forged `CONTAINER_NAME` from a local user.** Dropped: its
  `_SYSTEMD_UNIT` is not `docker.service`.
- **Customer log hosts.** A host that carries a Log Collector for customer
  logs also has a Host Agent, so it gets a system instance; its roxyd and
  REproduce units are product units and their lines are collected.
- **A host without a node.** Covered: the system instance needs no node.

## 6. Acceptance criteria

1. On a host with no checkpoint, the journal collector sends every retained
   entry of a selected source, oldest first, each as an `OpLog` whose time is
   the entry's realtime stamp.
2. Only entries meeting §4.2's table are sent; a `logger`, a user-session
   process, an unlisted unit and a forged `CONTAINER_NAME` are not.
3. Priorities 0–7 map as §4.2 says; Docker stdout is Info, stderr Error.
4. After a crash, a Giganto outage or a `journalctl` restart, nothing
   acknowledged is resent more than one acknowledgement window again and
   nothing is lost while the journal still holds it.
5. A journal vacuum past the saved cursor produces exactly one lost-interval
   warning, which is visible in Web.
6. Each Rust component under systemd writes `<N>`-prefixed, uncoloured lines
   without its own timestamp; a multi-line event is one journal entry; a panic
   is stored at priority 3; a terminal run is unchanged.
7. Every listed component refuses a configuration or command line naming
   `log_path` / `--log-path` with the "removed" message.
8. In a product install, every aice-web-next and bootroot container logs to the
   journal and `docker logs` still works; the `cron-logs` volume is gone.
9. Giganto deletes OpLog older than `oplog_retention` and other data older than
   `retention`, independently; both are readable and settable through
   `config` / `updateConfig` and the Data Store form.
10. REview installs one system REproduce with a journal collector on every
    host with a connected Host Agent, including a core-only host with no node,
    without an operator action; it appears in `systemLogCollectorList`, and its
    Data Store can be changed and its build updated there (§4.9, §4.10).
11. The Operational Logs page is visible only with `operational-logs:read`;
    saving a role with it but without `customers:access-all` is refused.
12. Searches honour every filter, reject ranges over 31 days, show results from
    the stores that answered with a warning naming one that did not, and each
    writes an audit-log entry.
13. Local-mode `oplog` records in the same Data Store never appear on the page.

## 7. Test plan

- reproduce unit tests: schema (`type = "journal"`, extra key refused, two
  journal collectors refused, mixed with `log` collectors); selection table on
  recorded `journalctl` JSON, including a forged `CONTAINER_NAME`, `_PID=1`
  lines with and without a listed `UNIT`, and wildcard edge cases; mapping
  (priorities, byte-array `MESSAGE`, 64 KiB cut, missing fields); checkpoint
  encode/decode, corrupt file, tmp sweep; acknowledged-position rules with
  dropped entries between kept ones; timestamp rule (same microsecond, more than
  1000 entries in one microsecond, a step back closes the stream and sends the
  held entry on a new one after the close ACK, a missing close ACK handled as a
  dropped stream, a repeated ACK acknowledges nothing new); lost-interval
  detection (gap at a resume, gap later in the same follow process, new
  `__SEQNUM_ID`, missing `__SEQNUM`, a replayed gap not warned twice);
  `journalctl` exit and restart; access-check error (a listable directory with
  an unreadable `system.journal`, run as a non-root user, and the same file
  readable).
- reproduce integration test (Ubuntu 24.04 runner or VM with systemd): REproduce
  as a `clumit-security` unit with `SupplementaryGroups=adm` reads the system
  journal (checks the `adm` ACL on 24.04), starts at the oldest entry of a
  multi-boot journal, follows new entries, resumes after `kill -9`, resumes
  across a reboot without skipping the previous boot's tail, and reports a gap
  after `journalctl --rotate` and `--vacuum-files=1` (also when the vacuum
  happens during a Giganto outage, reported at reconnect, and when it happens
  while the follow process and the stream stay alive behind back-pressure: at
  least one warning when reading resumes if an entry the test wrote is missing;
  if all test entries arrive, the warning count is recorded without asserting
  zero, since unselected entries may still have been lost, while exact counts
  are asserted only with the deterministic fake journalctl); a `MESSAGE` over 4096
  bytes arrives whole; against Giganto 0.31.0 the records are returned by
  `opLogRawEvents` with the expected `sensor` and `serviceName`, alongside a
  `log` collector on the same connection.
- Per component: under `systemd-run --unit=t --pipe` (or a test unit), lines
  carry `PRIORITY`, have no ESC byte, multi-line events stay single entries,
  a panic is priority 3; refusal of `log_path`.
- giganto: `oplog_retention` default and parsing; retention pass deletes OpLog
  and other data by their own windows; GraphQL `config` / `updateConfig`
  round-trip.
- review: §4.9 — every row of the install-step table (including a row whose
  newest attempt succeeded but has no instance, and a refusal before any
  ledger row); install on hosts with and without a node and alongside a node
  Log Collector; one install for concurrent triggers; Rollback/Hold by
  capability; UUID keys appended to `install_keys`; configure after a
  successful install without waiting 10 minutes; a maintenance-gate refusal
  retried at release, other refusals in `lastRefusal` with the one-hour
  wait; the chosen store persisted on first configuration, kept while
  unreachable, replaced only when removed; `get_config` from the row; build
  retention keeps the system build; node `update`/`remove` refused with
  `SystemInstance`, the system update path not refused; `inFlightInstalls` /
  `latestInstall` leave out every system key; the three GraphQL operations
  guarded to System Administrator; `oplogRetention` with an older Giganto
  (query and mutation retried without it, never pushed) and a stored text
  without it (compared and pushed with the live value).
- aice-web-next: `buildOperationalLogsDispatchContext` refusals; permission gate
  and role-save refusals (adding the permission without access-all, removing
  access-all while keeping it); query building per filter (one host / all, one
  source / all, level subsets); "ours" re-check; merge of several stores and
  levels; partial result warning; 31-day limit; audit entries; SAN display
  mapping; collectors view (Data Store picker, update, attempt state); bundle
  transform adds `logging: journald` to every kept service; cron output.
- Measurement (recorded in the PR): a 31-day search for a text that matches
  nothing, on a store holding 31 days at 25,000 records per day per host for 5
  hosts; if it exceeds 30 s, open a Giganto issue for a bounded scan
  (`spawn_blocking`, scan limit with a resume cursor).
- Human checks after release: end-to-end on a fresh install — module, REview,
  roxyd, bootroot-agent and container lines appear in Web within a minute;
  stopping one Data Store shows the partial-result warning.

## 8. Work items

One pull request each. Issues outside aicers/reproduce are written by hand
from this RFC.

| # | Repository | Work | Depends on |
| --- | --- | --- | --- |
| 1 | aicers/reproduce | Journal collector (§4.1–§4.4) and journal-native output of REproduce's own logs (§4.6) | aicers/reproduce#978, #981, #982 |
| 2 | aicers/giganto | `oplog_retention` (§4.8) | — |
| 3 | aicers/giganto | Journal-native output, remove `--log-path` (§4.6) | — |
| 4a | aicers/review-database | System-instance table (§4.9) | — |
| 4b | aicers/review-web | Backend trait methods and GraphQL `systemLogCollectorList`, `setSystemLogCollectorDataStore`, `updateSystemLogCollector`; `inFlightInstalls`/`latestInstall` leave out system attempts (§4.9) | 4a |
| 4 | aicers/review | System instance: reconcile, outcome recording, configuration, `get_config`, status, build retention (§4.9) | aicers/review#2369, 1, 4a, 4b |
| 5 | aicers/review | `oplogRetention` in the Giganto config client with the compatibility rules of §4.9; journal-native output; remove `log_path` (§4.6, §4.9) | 2 |
| 6 | aicers/aice-web-next | Operational Logs page, permission, dispatch helper, search audit; refresh the vendored `schemas/review.graphql` (§4.10) | 4, 5 |
| 7 | aicers/aice-web-next | Operational log collectors view; Data Store `oplog_retention` field; vendored schema refresh (§4.10) | 4, 5 |
| 8 | aicers/aice-web-next | journald driver in the product bundle; cron output to stdout (§4.7) | — |
| 9 | aicers/bootroot | journald driver in the deploy compose; bootroot-agent journal-native output (§4.6, §4.7) | — |
| 10 | aicers/piglet | Journal-native output, remove `log_path` incl. `resolve_log_path` (§4.6) | — |
| 11 | aicers/hog | Journal-native output, remove `log_path` (§4.6) | — |
| 12 | aicers/crusher | Journal-native output, remove `log_path` (§4.6) | — |
| 13 | petabi/reconverge | Journal-native output, remove `log_path` (§4.6) | — |
| 14 | aicers/roxyd | Journal-native output, remove `log_path` and `ROXYD_LOG_PATH` (§4.6) | — |
| 15 | aicers/bootler | Pins for 1–14; drop the `log_path` header line of `roxyd.toml` (`core/src/roxyd.rs:1650-1654`; goldens `:3878-3892`, `core/src/verify.rs:9731`, `:9908`, `:9916`, `:10235`) and `log_path` statements in `docs/modules.md` | 1–14 |

Coordination: aice-web-next RFC 0006
(`rfcs/0006-unsupervised-engine-configuration.md`) has petabi/reconverge and
giganto issues that referred to the withdrawn logging issues; items 3 and 13 are
their replacements.
