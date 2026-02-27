# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Peer init handshake now validates response/request PeerCode.
- Aligned `to_cert_chain` semantics: empty or invalid PEM input now returns an
  explicit error instead of an empty certificate chain. This improves mTLS
  security by treating zero-certificate chains as a failure condition.

### Fixed

- Fixed `SequenceGenerator` by using `AtomicU64` + CAS (`fetch_update`) to
  prevent duplicate sequence issuance during concurrent reset races.
  The generator now keeps state in one atomic value with deterministic rules:
  reset to `[date_key, epoch=0, counter=1]` only on newer dates, ignore stale
  dates, and wrap `epoch` (`255 -> 0`) when counter overflow occurs.
- Fixed an issue where combined search results could report incorrect previous/next
  page availability in giganto cluster mode, affecting pagination.
- Fixed `check_address`/`check_port` so `(Some(filter), None)` no longer passes.

## [0.26.2] - 2026-02-12

### Added

- Exposed `count` and `size` fields on `StatisticsDetail` in the
  `statistics` GraphQL response. These optional fields provide raw
  packet/event counts and byte totals, decoupling clients from
  the ingest sender's period configuration.

### Changed

- Improved `OpLog` migration logging to record skipped entries during the
  migration process.
- Updated root certificate loading to parse and include all certificates from a
  single PEM file, instead of only using the first certificate. Users can now
  supply a PEM file containing multiple root certificates and have all of them
  correctly added to the trust store.

### Fixed

- Fixed sub-second timestamp corruption in pcap file generation. The `pcap`
  GraphQL API was using bitwise AND (`&`) instead of modulo (`%`) when
  reconstructing the nanosecond portion of packet timestamps, causing incorrect
  timestamp values in `tcpdump` output.
- Fixed `OpLog` export API that was broken due to outdated DB key format usage.
  The export implementation now uses the correct timestamp-prefix key format
  (`[timestamp:8][sequence_number:8]`) instead of the old sensor-prefix format.
- Fixed TCP `CWR` flag value from `0x08` to `0x80`.

## [0.26.1] - 2025-12-18

### Changed

- Relocated the `compression` field from `ConfigVisible` to
  `Config::compression` to ensure the configuration is applied consistently.
- Updated the default value of `compression` to `false`, maintaining backward
  compatibility with existing deployments where compression was not previously
  enabled.

## [0.26.0] - 2025-12-03

### Added

- Enhanced raw event structures with packet count and size information:
  - Added `orig_pkts`, `resp_pkts`, `orig_l2_bytes`, `resp_l2_bytes` fields to
    all raw event structures.
  - Added `duration` field to all raw event structures to store session
    duration.
  - Updated migration functions to handle new event structure fields.
- Added `compression` configuration option to enable or disable RocksDB
  compression. Defaults to `true` (enabled). Giganto validates the compression
  setting on startup and reports an error if it doesn't match the database's
  compression scheme. Changing compression settings is not supported for
  existing databases.
- Added support for `MalformedDns` events, including database storage, ingest,
  publish, and GraphQL API functionality.
- Introduced a new feature flag, `cluster`, to enable or disable Giganto's
  cluster functionality.
  - When `cluster` is enabled (default), Giganto connects to other instances in
    the cluster and shares data.
  - When `cluster` is disabled, Giganto operates in standalone mode, without
    connecting to other instances. It avoids using GraphQL client functionality,
    allowing it to generate the `schema.graphql` file independently.
- Added a new binary target, `gen_schema`, to generate the GraphQL schema file
  from the API definitions.
- Added `build.rs` to automatically generate the GraphQL schema file during the
  build process.
- Added client certificate support for GraphQL API to enable mutual TLS (mTLS)
  authentication when communicating with other Giganto instances in a cluster.
- Added `start_time` field to all protocol event structures for improved
  temporal tracking and consistency.
  - The `start_time` field represents the session start time.
  - Raw event keys, which previously used the session start time, now use the
    actual raw event creation timestamp provided by the sensor application.
- Added RADIUS protocol support with the `RadiusRawEvent` struct and the GraphQL
  APIs (`radiusRawEvents`, `searchRadiusRawEvents`).
- Added `countByProtocol` GraphQL API for precise event counting by protocol
  type (Session, DNS, HTTP). This feature is gated behind the `count_events`
  feature flag and is intended for quality checks and testing. The API iterates
  over all keys in the database to provide exact counts, which may be expensive
  on large datasets.

### Changed

- Renamed configuration field `max_sub_compactions` to `max_subcompactions` to
  align with RocksDB naming conventions.
- Modified FTP event structure to store multiple commands as `Vec<FtpCommand>`
  instead of single command fields. This change preserves the complete command
  history of FTP sessions, enabling better threat analysis and session tracking.
  The FTP GraphQL API now returns a `commands` array containing all commands
  and their responses from a session.
- Refactored Publish API to use request type-driven processing. The Publish
  API now processes requests based on their specific request type rather than
  the client's `NodeType`. This change decouples request handling from client
  identity, allowing any client to make any type of request regardless of their
  `NodeType`. This increases flexibility and removes artificial limitations on
  client capabilities.
- Updated `giganto-client` dependency to support the new request type-driven
  processing model.
- Extracted communication-related logic into a separate module named `comm`.
  This refactoring removes common functionality from `main.rs`, preventing
  redundant declarations when adding additional binaries.
- Migrated web server from `warp` to `poem` framework for better maintainability
  and future OpenAPI support. The GraphQL endpoint and playground functionality
  remain unchanged.
- Consolidated HTTP event fields to improve data structure efficiency and reduce
  redundancy. Changes include:
  - Merged `orig_filenames` and `resp_filenames` into single `filenames` field
  - Merged `orig_mime_types` and `resp_mime_types` into single `mime_types` field
  - Renamed `post_body` field to `body` for consistency
  - Updated migration functionality to handle field consolidation from older versions
- Removed the `last_time` field from all network raw event structs. The
  combination of `start_time` and `duration` sufficiently represents the event’s
  time range, making `last_time` redundant.
- Updated compatibility versions:
  - Updated `INGEST_VERSION_REQ` to ">=0.26.0,<0.27.0".
  - Updated `PUBLISH_VERSION_REQ` to ">=0.26.0,<0.27.0".
  - Updated `COMPATIBLE_VERSION_REQ` to ">=0.26.0,<0.27.0".
  - Updated `PEER_VERSION_REQ` to ">=0.26.0,<0.27.0".

### Removed

- Removed migration support for versions earlier than v0.21.0. Database
  migration is now only supported from v0.21.0 and above. This change removes
  legacy migration code and improves maintainability by eliminating support for
  outdated application versions.

### Fixed

- Fixed packet extraction request routing to ensure requests are only sent to
  actual sensor connections. Connection information is now stored in
  `pcap_sensors` only when the connected agent is identified as a sensor
  (containing "piglet" in the certificate).
- Fixed deserialization issue for GraphQL `StringNumber` fields in cluster mode.
  String representations of numbers (e.g., "123456") are now correctly parsed
  into wrapped integer types such as `StringNumberI64(i64)` or `StringNumberU64(u64)`.
- Modified `retain_periodically` function to stop further delete operations on a
  column family when a delete operation fails, preventing cascading failures
  and reducing excessive error logs.
- Fixed the database retention logic for `oplog` and `periodic time series` with
  non-standard key formats. `oplog` now uses timestamp-based range deletion
  instead of sensor-based iteration. `periodic time series` retention is
  temporarily disabled until proper policy-based retention logic is implemented.
- Fixed config update consistency issue where in-memory settings could diverge
  from the persisted config file if backup or write operations failed.
  `Settings::update_config_file` now defers in-memory state mutation until
  after both backup and file write operations succeed, ensuring memory and disk
  remain synchronized.

### Security

- Implemented client certificate authentication for GraphQL endpoint to prevent
  unauthorized access. Clients must now provide valid certificates signed by a
  trusted CA to access the GraphQL API.

## [0.25.1] - 2025-07-08

### Changed

- Updated the roxy library dependency to 0.4.0 to support accurate measurement
  of disk usage at the correct data store path.

## [0.25.0] - 2025-06-18

### Changed

- Updated HTTP header field name from `referrer` to `referer` in GraphQL APIs
  and data structures to maintain accuracy and direct correspondence with the
  HTTP `Referer` header standard. This affects HTTP-related GraphQL queries and
  responses where the field was previously named `referrer`.
- Modified search range boundary handling for consistency. Currently, the
  handling of range search with a single input is inconsistent between time and
  address/port. To address this inconsistency, the `check_address` and
  `check_port` functions have been modified to follow the same behavior as time
  range handling.
  - only the start value is provided: Retrieves all results greater than or
    equal to the start value.
  - only the end value is provided: Retrieves all results less than the end value.
- Updated compatibility versions for QUIC communication and database migration
  - Updated `INGEST_VERSION_REQ` to ">=0.23.0,<0.26.0".
  - Updated `PUBLISH_VERSION_REQ` to ">=0.23.0,<0.26.0".
  - Updated `COMPATIBLE_VERSION_REQ` to ">=0.24.0,<0.26.0".
- Updated `PEER_VERSION_REQ` to ">=0.25.0,<0.26.0" to ensure compatibility
  between Giganto instances in the cluster. This change was made to reflect the
  GraphQL API updates, specifically the change of the `referrer` field name to
  the standard spelling `referer`.

## [0.24.3] - 2025-05-23

### Changed

- Logging behavior no longer considers the debug mode. Previously, logging
  behavior depended on both `log_path` and the build type(debug/release). Now,
  whether logs are written to stdout or to a file is determined solely by the
  presence of `log_path`.
- Giganto now creates a backup before overwriting the config via the
  `updateConfig` GraphQL API. If reading the config fails, it automatically
  restores from the backup, both during `updateConfig` calls and at startup.
- Replaced `--log-dir` with `--log-path` in command-line interface. Now the log
  file path can be specified directly rather than combining a directory and a
  fixed filename.
- Removed dependency on LOG_FILENAME environment variable by eliminating the
  .cargo/config.toml file.

## [0.24.2] - 2025-04-08

### Changed

- Adjusted the `pcap` GraphQL API with the following improvements:
  - Reduced the number of processed packets from up to 1,000 to up to 10,
    lowering resource usage and improving performance when handling large HTTP
    sessions. Ten packets are generally sufficient for client-side inspection.
  - Simplified PCAP generation by removing the intermediate step of reading a
    temporary file into memory and piping it into `tcpdump` via stdin. Now,
    `tcpdump` reads directly from the temporary file, reducing overhead and
    improving efficiency.

## [0.24.1] - 2025-03-14

### Changed

- Documentation of the following GraphQL APIs is updated:
  - `dnsRawEvents`
- Changed default GraphQL API port to 8443.
- Renamed the log file from giganto.log to data_store.log.

## [0.24.0] - 2025-02-19

### Added

- Added the `load_connection_by_prefix_timestamp_key` function and
  `TimestampKeyExtractor` trait to enable querying of keys prefixed with `timestamp`.
- The `opLogRawEvents` GraphQL API no longer requires `agentId` and now accepts
  it as an optional parameter. Additionally, the API response now includes logs
  from all agents displayed in chronological order, rather than being limited to
  the logs of a single agent.

### Changed

- Updated `PEER_VERSION_REQ` to ">=0.24.0<0.25.0" to ensure compatibility
  between Giganto instances in the cluster. This change reflects updates of
  GraphQL API.
- Updated the giganto-client library dependency to 0.22.0. Since this update
  does not break backward compatibility for modules communicating with Giganto
  via the QUIC protocol, the related version requirements have been adjusted as
  follows:
  - Updated `INGEST_VERSION_REQ` to ">=0.23.0,<0.25.0".
  - Updated `PUBLISH_VERSION_REQ` to ">=0.23.0,<0.25.0".
- Modify the code related to migration.
  - Changed `COMPATIBLE_VERSION_REQ` to ">=0.24.0,<0.25.0".
  - Added migration function `migrate_0_23_0_to_0_24_0_op_log`. This function
    performs a migration to change the key and value of `Oplog`.
- Several changes are made to configuration management via the GraphQL API:
  - The `setConfig` GraphQL API has been renamed to `updateConfig` to better
    reflect its functionality. This API not only accepts a new configuration but
    also applies it by reloading the system. Upon success, the API returns the
    new config. The fields that can be updated via `updateConfig` are the same
    as those retrievable via the `config` GraphQL API.
  - The `updateConfig` GraphQL API returns an error if the provided `new` config
    is an empty string. It also returns an error if the `new` is the same as the
    current configuration, which can be retrieved via the `config` GraphQL API.
    Additionally, an error is returned if the `new` config content is invalid.
    If an error occurs, the update request is not applied.
  - The `config` GraphQL API no longer returns the `logDir`, `addrToPeers`, and
    `peers` fields.
  - The `retention` field in the `config` GraphQL API response now follows the
    "{days}d" format to align with the request format used in `setConfig`
    GraphQL API.
- The term `timestamp` and `timestamps` are replaced with `time` and `times` in
  event structs where the type is `DateTime<Utc>`. This change impacts GraphQL
  APIs that return event data or accept filter parameters that used timestamp.
  Additionally, the JSON files generated by the `export` GraphQL API also use
  the new term.
- Documentation of the following GraphQL APIs is updated:
  - `connRawEvents`
  - `networkRawEvents`
  - `ftpRawEvents`
  - `httpRawEvents`
  - `tlsRawEvents`
  - `kerberosRawEvents`
  - `ldapRawEvents`
  - `mqttRawEvents`
  - `nfsRawEvents`
  - `smbRawEvents`
  - `smtpRawEvents`
  - `sshRawEvents`
  - `dhcpRawEvents`
  - `bootpRawEvents`
  - `dceRpcRawEvents`
  - `rdpRawEvents`
  - `ntlmRawEvents`
- `log_dir` is no longer a configuration item. To specify the log directory, it
  is required to use an optional command-line argument `log-dir`.
- Logging behavior related to command line arguemtn `log-dir` is as follows:
  - If `log-dir` is not provided, logs are written to stdout using the tracing library.
  - If `log-dir` is provided and writable, logs are written to the specified
    directory using the tracing library.
  - If `log-dir` is provided but not writable, Giganto will terminate.
  - Any logs generated before the tracing functionality is initialized will be
    written directly to stdout or stderr using `println`, `eprintln`, or similar.

### Removed

- Removed OS-specific configuration directory.
  - Linux: $HOME/.config/giganto/config.toml
  - macOS: $HOME/Library/Application Support/com.cluml.giganto/config.toml
- Removed the GraphQL API `csvFormattedRawEvents`.

## [0.23.0] - 2024-11-21

### Added

- Added GraphQL API `csvFormattedRawEvents` that returns the values of raw
  events of the request protocol in csv format String, delimited by tab.

### Changed

- Remote configuration is no longer stored in a temporary file, nor does it
  overwrite the existing configuration file.
- Changed GraphQL APIs `config` and `setConfig` to return error when using local
  configuration.
- Modified the repair mode to operate only with a local configuration. Giganto
  now terminates if the repair option is specified without the `-c` flag.
- The term source is replaced with the term sensor, resulting in the following
  major changes:
  - The `sources` column family in the DB is replaced with `sensors` column
    family. Running this version of Giganto will migrate the existing data in
    `sources` column familiy to `sensors` column family.
  - The `sources` GraphQL API is renamed to `sensors`.
  - The `sourceId` field in the `export` GraphQL API is renamed to `sensorId`.
  - The `source` field in the filter parameters of all GraphQL APIs is changed
    to `sensor`.
- Update the compatibility version of the quic communication modules, due to the
  update of giganto-client to 0.21.0.
  - Changed `INGEST_VERSION_REQ` to ">=0.23.0,<0.24.0".
  - Changed `PUBLISH_VERSION_REQ` to ">=0.23.0,<0.24.0".
- Updated `PEER_VERSION_REQ` to ">=0.23.0,<0.24.0" to ensure compatibility
  between Giganto instances in the cluster. This change reflects updates to the
  GraphQL API version and event protocol, which require consistent versions
  across all nodes.

### Removed

- Removed the GraphQL API `setAckTransmissionCount` as the entire configuration
  is now sent at once when modified through the UI.

### Fixed

- Fixed a missing update to the schema.graphql file necessary for communication
  within the Giganto cluster.

## [0.22.1] - 2024-10-22

### Fixed

- Fixed `Connection` of type `PcapSources` to `Vec<Connection>`. This change
  will allow giganto to find the latest `Connection` and extract pcap even if it
  detects a late disconnect from ingest.

## [0.22.0] - 2024-10-04

### Added

- Added `required` option to `ca_certs` to provide an error message when there
  is no `--ca-certs` execution option.

### Changed

- Changed `config` GraphQL API to include a field indicating whether the
  configuration is local or remote.
- Update the compatibility version of the quic communication modules.
  - `PEER_VERSION_REQ` to ">=0.21.0,<0.23.0".
  - `INGEST_VERSION_REQ` to ">=0.21.0,<0.23.0".
  - `PUBLISH_VERSION_REQ` to ">=0.21.0,<0.23.0".

### Fixed

- Fixed to create `Config` variable normally when running without config file.

### Security

- Updated dependency for security vulnerabilities.
  - Updated async-graphql to version 7.0.11.

## [0.21.0] - 2024-09-23

### Changed

- Updated the version of giganto-client from 0.15.2 to version 0.19.0. Updating
  to this version results in the following changes.
  - Updated the version of quinn, rustls from 0.10, 0.21 to 0.11, 0.23. With the
    update to this version, the usage of the quinn and rustls crates has
    changed, so code affected by the update has also been modified.
  - Modified code and structures based on changes to the conn, http, smtp, ntlm,
    ssh, tls protocols field.
  - Support bootp, dhcp protocol events.
- Changed to receive events in a unit of 100.
- Modified to append the kind value to the filename when extracting a file for a
  protocol for which a kind value exists.
- Applied code import ordering by `StdExternalCrate`. From now on, all code is
  expected to be formatted using `cargo fmt -- --config group_imports=StdExternalCrate`.
- Changed cluster related configuration field names.
  - `peer_address` to `addr_to_peers`
  - `address` in `peers` to `addr` and `host_name` in `peers` to `hostname`
- Changed GraphQL APIs to return `StringNumber` instead of integers beyond `i32`
  in all applicable APIs.
- Changed command line interface.
  - Removed `cert`, `key`, `root` fields from config file.
  - Added cli options `-c`, `--cert`, `--key` and `--ca-certs`.
- Renamed GraphQL API `gigantoConfig` to `config` and updated it to respond the
  full configuration.
- Renamed GraphQL API `setGigantoConfig` to `setConfig`. The endpoint now
  accepts a full configuration as a TOML string and returns `Result<bool>`,
  instead of `Result<String>`.
- Update the compatibility version of the quic communication modules.
  - `PEER_VERSION_REQ` to ">=0.21.0,<0.22.0".
  - `INGEST_VERSION_REQ` to ">=0.21.0,<0.22.0".
  - `PUBLISH_VERSION_REQ` to ">=0.21.0,<0.22.0".

### Removed

- Removed `unsafe` block in `write_run_tcpdump` while creating a temporary file.
- Removed migration code less than 0.15.3.

### Security

- Updated dependency for security vulnerabilities.
  - Updated quinn-proto to version 0.11.8.
  - Updated openssl to version 0.10.66.

## [0.20.0] - 2024-05-17

### Added

- Added GraphQL API `ping` and mutation `stop`, `reboot`, `shutdown`.
- Added rocksdb's `increase_parallelism` option. This option is set by reading
  the value from `number_of_thread` in config file.
- Added rocksdb's `set_max_subcompactions` option. This option is set by reading
  the value from `max_sub_compactions` in config file.

### Changed

- Modified logging behavior for debug and release builds.
- Changed logs to stdout and file.
- Modify to extract kind/source correctly on export of `secu log`.
- Modify `retain_periodically` function to run as a separate thread.
- Added the `.export` tag to the file being exported. This tag is removed after
  the file is finished exporting.
- Updated `set_giganto_config` function to record requested configuration
  changes to a temporary toml file. Given the original configuration file name
  as `giganto.toml`, the temporary file is named as `giganto.toml.temp.toml`.
  - If the reload trigger succeeds, the new configuration is applied from the
    temporary file; otherwise, the temporary file is deleted.
- Changed configuration field names.
  - `ingest_address` to `ingest_srv_addr`.
  - `publish_address` to `publish_srv_addr`.
  - `graphql_address` to `graphql_srv_addr`.
  - `roots` to `root` to handle using a single root.
- Update dependency for security vulnerabilities.
  - Update rustls to version `0.21.12`.
  - Update h2 to version `0.3.26`.
- Changed `PEER_VERSION_REQ` to ">=0.19.0,<0.21.0".
- Changed `INGEST_VERSION_REQ` to ">=0.15.0,<0.21.0".
- Changed `PUBLISH_VERSION_REQ` to ">=0.17.0,<0.21.0".

### Removed

- Remove `max_background_jobs` rocksdb option. This option is automatically set
  to the appropriate value when `increase_parallelism` is set.

## [0.19.0] - 2024-02-22

### Added

- Added migration functionality in 0.19.0. This feature deletes the values of
  existing keys in netflow5/netflow9/seculog from versions prior to 0.19.0 and
  inserts the values of new keys.

### Changed

- Modify the `sources` GraphQL API to return results that also include sources
  from its peers.
- Changed the prefix of the `Netflow5`/`Netflow9`/`SecuLog` db key to source.
- Modify the related GraphQL APIs as the db keys for `Netflow5`/`Netflow9`/`SecuLog`
  have been changed to `Netflow5RawEvent`, `Netflow9RawEvent`, and `SecuLogRawEvent`
- Changed `PEER_VERSION_REQ` to ">=0.19.0,<0.20.0".
- Changed `PUBLISH_VERSION_REQ` to ">=0.17.0,<0.20.0".

## [0.18.0] - 2024-02-16

### Changed

- Reverted the change of logging from `log-broker` to `tracing`.

### Fixed

- Fixed the default port to `8442`.

## [0.17.0] - 2024-01-24

### Added

- Added the ability to filter via `agent_id` in the filter of a GraphQL query
  requesting a sysmon events.
- Added `SmtpRawEvent` to the return value union of `networkRawEvents` GraphQL API.
- Added `RunTimeIngestSources` type that checks for information from source that
  is connected to ingest in real time. This type is not currently used, but may
  be used in the future to provide real-time connection information.

### Changed

- Modify GraphQL schema file due to the addition of the `agent_id` field.
- Changed `PEER_VERSION_REQ` to ">=0.17.0,<0.18.0".
- Changed `PUBLISH_VERSION_REQ` to ">=0.17.0,<0.18.0".
- Modify `export` GraphQL API to set the extension of the extract file according
  to the export type.

### Fixed

- Fix the part of the `export` query in the GraphQL API about validating filters
  for protocols.
- Fix to initialize `ingest_sources` value from `sources` cf on giganto startup.
  This change is intended to ensure that `IngestSources` provide all source
  information for stored data and `RunTimeIngestSources` provide real-time
  connection source information.

## [0.16.0] - 2024-01-08

### Added

- Added to call more flushes within the `handle_data` function of `ingest` that
  receive raw events. This change ensures that data is saved in all cases where
  the `handle_data` function terminates, such as when an `error` occurs.
- Added functionality to control the sending of acknowledgments.
  - Set the `AckTransmissionCount` by reading from the config file.
  - Changed the type of ack transmission count checked in `ingest` from
    `const u16` to `AckTransmissionCount`(`Arc<RwLock<u16>>`).
  - Added `setAckTransmissionCount` GraphQL API to set the ack transmission
    count. This query changes the `AckTransmissionCount` used in ingest and
    `ack_transmission` in the config file to the input `count` value.
- Added documentation for implementing cluster-supported GraphQL APIs in `docs/guide-giganto-cluster-graphql.md`.
- Added `ConvertGraphQLEdgesNode` derive macro that implements `From` trait from
  GraphQL client structs to project structs.
- Supported `log-broker` to send/receive operation log with redis server.
  - Set the redis server with `redis_log_address`, `redis_log_agent_id` and
    `redis_log_fetch_interval` in configuration options.

### Changed

- Modify the `setGigantoConfig` and `gigantoConfig` queries in the GraphQL API
  to read/write the ack transmission count.
- Modify the `setGigantoConfig` and `gigantoConfig` query in the GraphQL API so
  that the fields that take integers read/write the config file for their
  respective types.
- Modify the `gigantoConfig` query in the GraphQL API so that config files that
  work in standalone mode can also be read correctly.
- Changed `export` GraphQL API's response value format from `{export_path}` to `{export_path}@{giganto_node_name}`.
- Changed logging from `tracing` to `log-broker`.
- Changed `PEER_VERSION_REQ` to ">=0.16.0,<0.17.0".
- Changed `PUBLISH_VERSION_REQ` to ">=0.16.0,<0.17.0".
- Added giganto cluster support for GraphQL and publish message requests.
- Added `requestFromPeer` argument to GraphQL API: `netflow5RawEvents`,
  `netflow9RawEvents`, `secuLogRawEvents`, `statistics`.

### Fixed

- Fix `retain_periodically`.

## [0.15.4] - 2023-11-22

### Added

- Added GraphQL API `sysmonEvents` to retrieve all sysmon events at once.

### Changed

- Change to use the `batched_multi_get_cf` provided by rocksdb for multi get search.
  - Since `batched_multi_get_cf` is used, add the prefix `batched` to the
    `multi_get_from_ts`/`multi_get_with_source` functions respectively.
- Changed manual boundary check to boundary checking via `iterator_cf_opt`.
- Rename type aliases `PacketSources` to `PcapSources`, `Sources` to
  `IngestSources`, and `StreamDirectChannel` to `StreamDirectChannels`; And move
  their definition location from `ingest.rs` to `main.rs`.
- Modified `retain_periodically`.
  - When disk usage exceeds `USAGE_THRESHOLD` delete old data until disk usage
    is reduced to `USAGE_LOW`.
  - Supports all column families.
  - The iterator stops processing data once it encounters data that is newer
    than the specified retention period.
- Moved `netflow` source to value from key.

## [0.15.3] - 2023-11-09

### Changed

- Changed `check_address` and `check_port` to have a close ended search where it
  will only return the events that contain the address or port for single input.

## [0.15.2] - 2023-11-09

### Changed

- Change `MessageCode::RawData` request processing code to send raw events to
  the Unsupervised Engine in the same format as `MessageCode::RangeData`.

## [0.15.1] - 2023-11-08

### Changed

- Moved `secu_log` source to value from key.

## [0.15.0] - 2023-11-08

### Changed

- Updated giganto-client to 0.15.0.
- Changed minimum/maximum version to 0.15.0 <= version < 0.16.0.

## [0.14.0] - 2023-11-07

### Added

- Added `--repair` option to only fix the database problem then terminated.
- Support `NetflowV5`, `NetflowV9` events. These events does not streamed to the
  Semi-supervised Engine or the Time Series Generator.
- Support `Seculog` events.
  - The `secuLogRawEvents` GraphQL API requires its kind. `wapples`, `mf2`,
    `sniper`, `aiwaf`, `tg`, `vforce`, `srx`, `sonicwall` `fgt`, `shadowwall`,
    `axgate`, `ubuntu`, `nginx`

### Changed

- Modified Kerberos event to support giganto-client.
- Changed `max_background_jobs` to 6 from 2.
- Changed minimum version to 0.13.1.

### Fixed

- Fix potential bug in `retain_periodically`.

## [0.13.1] - 2023-09-18

### Changed

- Change the `statistics` GraphQL API.
  - Removed `core` as an argument to the query. Also changed the condition of
    source to allow searching for `multiple sources`.
  - Provides statistics data by `source`/`time`/`protocol`.
  - If the statistics data type is `statistics`, provide `bps`/`pps`.
  - If it's of type `network` (network-sourced events collected by the Sensor),
    provide `eps`.
  - If there is no value for the protocol field in the filter, statistics are
    provided for `all protocol`.
  - If filter has no value for the time field, it will provide the most `recent`
    statistics.
- Add feature to generate benchmark statistics for ingest events.
- Modify to execute flush when giganto down.

## [0.13.0] - 2023-08-28

### Added

- Add GraphQL API `statistics` to read data from `statistics` store. The result
  format is `Protocol/Size/Count`.
  - `Protocol`: target protocol name like `Statistics`, `Http`, `Dns`.
    `Statistics` is the input traffic statistics of the collector device.
  - `Size`: packet size for `Statistics` or 0 for other protocols.
  - `Count`: packet count for `Statistics` or event count for other protocols.
- Add key generation feature for intuitive data lookup of database in giganto.
  - `StorageKeyBuilder`: This is a builder structure for dynamically generating
    keys. Depending on whether you have 2 or 3 keys, call the
    `start`/`mid`/`end` function to set the keys.
  - `StorageKey`: A structure that stores lookup keys generated by `StorageKeyBuilder`.
  - `KeyExtractor`: A trait for calling the value to be set by the key.
- Supports 14 sysmon events.
- Added `search[sysmon type]Events` GraphQL APIs for sysmon event supported by giganto.

### Changed

- Replaced `lazy_static` with the new `std::sync::OnceLock`.
- Modify `pcap_with_data` test function to compare times based on utc timezone.
- Change the key of `statistics` store to `source + core id + timestamp` not to
  overwrite statistics data from other core of same machine. When Giganto is
  loading with old DB version, the old data will be removed because it's
  possible to be overwritten by other core's data.
- Change `export` GraphQL API to support `statistics` store. This change makes
  it possible to export statistics data of only core 0 of the collector device.
  This will be fixed in next change.
- Remove unused `time()` from `RawEventFilter` trait.
- Modify to use `Networkfilter` in GraphQL APIs requesting sysmon events.
- Modify statistics migration version to 0.13.0 from 0.12.4.

### Fixed

- Fixed to only generate the `collect_records` error message when an error event
  exists, and applied the same change to `export`.
- Fixed `export` GraphQL API to export statistics data for all cores.

## [0.12.3] - 2023-07-10

### Changed

- Fixed fields of `FtpRawEvent` and `FtpJsonOutput`.
- Modified `collect_records` to continue collecting even if error data is
  included in the data.

### Fixed

- Fixed warning from release build.

## [0.12.2] - 2023-07-04

### Added

- Supports the SMB protocol.
- Supports the NFS protocol.

## [0.12.1] - 2023-06-26

### Added

- Supports the TLS protocol.
- Added migration functionality in `0.12.0`. This feature adds values for new
  fields (`orig_filenames`, `orig_mime_types`, `resp_filenames`, `resp_mime_types`)
  to `Http` in versions 0.12.0 and earlier.

## [0.12.0] - 2023-06-20

### Added

- added Giganto clustering functionality. This feature connects giganto
  peer-to-peer, and connected gigantos share each other's `peer` list and
  connected `source` list.
- Supports the LDAP protocol.

### Changed

- Supports the expanded HTTP protocol.
- Modify `proto` field of `Ftp`, `Mqtt`, `Ldap` to u8 from u16.
- Modify the processing part of the Unsupervised Engine's data request.
  - Modify to handle network, log, and time series data requests with `ReqRange`
    and `RequestRange`.
  - Add to handle `Timeseries` requests in `MessageCode::RawData`.
  - Modify `multi_get_with_source` to return in the form of `Vec<(i64, String, Vec<u8>)>`.

## [0.11.0] - 2023-05-16

### Changed

- Modify the certificate verification.
- Update quinn to version 0.10 and rustls to version 0.21 for giganto-client
  version 0.7.0.

## [0.10.2] - 2023-05-12

### Added

- Supports the MQTT protocol.
- Add `cfg path` fields to Settings. This path is used to fetch/modify giganto's
  config.

### Fixed

- Fixed to check for DB compatibility version.

## [0.10.1] - 2023-05-02

### Added

- Add event search GraphQL API for protocols supported by `giganto`. (`dns`,
  `conn`, `rdp`, `smtp`, `ntlm`, `kerberos`, `ssh`, `DceRpc`,`ftp`)

## [0.10.0] - 2023-04-28

### Added

- Add GIGANTO DB version compatibility check.
- Add a publish API to return the source, raw_events from the source, timestamps
  for the Unsupervised Engine.
- Supports the FTP protocol.
- Add a GraphQL API for `searchHttpRawEvents`.

## [0.9.0] - 2023-04-03

### Added

- Add GraphQL API to return source list.

### Changed

- Change the format of data sent to the Unsupervised Engine from the publish
  module. ([ref](https://github.com/aicers/giganto-client/issues/9))

## [0.8.0] - 2023-03-30

### Added

- Add Giganto Restart processing.
- Add more fields to `Dns`, `Conn`, `Http`.
- Add common fields to network events.
- Publish support Packet request/response through QUIC.
- Add Packet store.
- Add GraphQL API for Packet.
- Add database options to config file.
- Add GraphQL API for config file.

### Changed

- Change field name `duration` to `last_time`. (Except Conn struct)
- Modify to receive and process `multiple sources` of stream request messages
  from the Semi-supervised Engine.
- Modify module name `ingestion` to `ingest`.
- Create giganto's communication part as a separate crate. (giganto-client)
- Move init tracing to giganto-client crate for oplog logging.
- Fix packet logic in ingest.
- Rocksdb compression type has changed to Lz4, zstd from snappy.
- Move giganto-client to separate repo [giganto-client](https://github.com/aicers/giganto-client).

## [0.7.0] - 2023-01-04

### Added

- Add export file to GraphQL API. (`csv`, `json` format support)
- Add `Statistics` column family. Receive and save traffic statistics from the Sensor.
- Save Giganto's `syslog` to a path written to `log_dir` in configuration file.
- Add `Oplog`. (Operation log)

### Changed

- Send different stream start message depending on the daemon.
- Check the write permission on `/data/logs/apps` directory.

## [0.6.0] - 2022-12-06

### Added

- Publish support protocol record data request/response through QUIC.
- Add periodic time series to GraphQL API.
- Add send `all` source network stream to the Semi-supervised Engine.
- Add more network data types. (`Ntlm`, `Kerberos`, `Ssh`, `DceRpc`)

### Changed

- The key in timeseries data includes timestamp.
- Change DNS answer field to `Vec<String>`.

### Removed

- Remove send network stream to the Semi-supervied Engine from database.

### Fixed

- The subject name, rather than the issuer name, in the client certificate is
  used as an identifier.

## [0.5.0] - 2022-11-17

### Added

- Adds `smtp` to receive and save SMTP event.
- Adds SMTP to GraphQL API.

### Changed

- Adds `answer` field of DNS event.

## [0.4.0] - 2022-11-01

### Added

- Publish support network event(conn, dns, rdp, http) stream data through QUIC.
- GraphQL API returns all network raw events.

### Changed

- Separate compatibility version check criteria for publish and ingestion.

## [0.3.0] - 2022-10-20

### Added

- Support periodic time series.
- GraphQL API supports filtering with source name, kind name of log, time range,
  IP address range, port range.
- Publish check protocol compatibility with connected Programs.
- Publish support log/period time series record data request/response through QUIC.
- Add Packets Request GraphQL API.
- Send acknowledgment of channel done messages sent by reproduce.

### Changed

- GraphQL API now accepts `filter`, which includes the source name, time range,
  IP address ranges, and port ranges.

### Fixed

- Fixed a bug returning wrong events when the time range is specified.

## [0.2.0] - 2022-10-04

### Added

- limit Maximum request page size. (Requests over 100 will be treated as 100)
- Check protocol compatibility with connected Programs.
- Accepts QUIC connections from subscribers.
- GraphQL API supports cursor-based pagination.
- GraphQL API takes `start` and `end` parameters to specify the time range of
  the query.

### Fixed

- A query for a certain source no longer returns events from other sources.

## [0.1.0] - 2022-09-16

### Added

- Initial release.

[Unreleased]: https://github.com/aicers/giganto/compare/0.26.2...main
[0.26.2]: https://github.com/aicers/giganto/compare/0.26.1...0.26.2
[0.26.1]: https://github.com/aicers/giganto/compare/0.26.0...0.26.1
[0.26.0]: https://github.com/aicers/giganto/compare/0.25.1...0.26.0
[0.25.1]: https://github.com/aicers/giganto/compare/0.25.0...0.25.1
[0.25.0]: https://github.com/aicers/giganto/compare/0.24.3...0.25.0
[0.24.3]: https://github.com/aicers/giganto/compare/0.24.2...0.24.3
[0.24.2]: https://github.com/aicers/giganto/compare/0.24.1...0.24.2
[0.24.1]: https://github.com/aicers/giganto/compare/0.24.0...0.24.1
[0.24.0]: https://github.com/aicers/giganto/compare/0.23.0...0.24.0
[0.23.0]: https://github.com/aicers/giganto/compare/0.22.1...0.23.0
[0.22.1]: https://github.com/aicers/giganto/compare/0.22.0...0.22.1
[0.22.0]: https://github.com/aicers/giganto/compare/0.21.0...0.22.0
[0.21.0]: https://github.com/aicers/giganto/compare/0.20.0...0.21.0
[0.20.0]: https://github.com/aicers/giganto/compare/0.19.0...0.20.0
[0.19.0]: https://github.com/aicers/giganto/compare/0.18.0...0.19.0
[0.18.0]: https://github.com/aicers/giganto/compare/0.17.0...0.18.0
[0.17.0]: https://github.com/aicers/giganto/compare/0.16.0...0.17.0
[0.16.0]: https://github.com/aicers/giganto/compare/0.15.3...0.16.0
[0.15.4]: https://github.com/aicers/giganto/compare/0.15.3...0.15.4
[0.15.3]: https://github.com/aicers/giganto/compare/0.15.2...0.15.3
[0.15.2]: https://github.com/aicers/giganto/compare/0.15.1...0.15.2
[0.15.1]: https://github.com/aicers/giganto/compare/0.15.0...0.15.1
[0.15.0]: https://github.com/aicers/giganto/compare/0.14.0...0.15.0
[0.14.0]: https://github.com/aicers/giganto/compare/0.13.1...0.14.0
[0.13.1]: https://github.com/aicers/giganto/compare/0.13.0...0.13.1
[0.13.0]: https://github.com/aicers/giganto/compare/0.12.3...0.13.0
[0.12.3]: https://github.com/aicers/giganto/compare/0.12.2...0.12.3
[0.12.2]: https://github.com/aicers/giganto/compare/0.12.1...0.12.2
[0.12.1]: https://github.com/aicers/giganto/compare/0.12.0...0.12.1
[0.12.0]: https://github.com/aicers/giganto/compare/0.11.0...0.12.0
[0.11.0]: https://github.com/aicers/giganto/compare/0.10.2...0.11.0
[0.10.2]: https://github.com/aicers/giganto/compare/0.10.1...0.10.2
[0.10.1]: https://github.com/aicers/giganto/compare/0.10.0...0.10.1
[0.10.0]: https://github.com/aicers/giganto/compare/0.9.0...0.10.0
[0.9.0]: https://github.com/aicers/giganto/compare/0.8.0...0.9.0
[0.8.0]: https://github.com/aicers/giganto/compare/0.7.0...0.8.0
[0.7.0]: https://github.com/aicers/giganto/compare/0.6.0...0.7.0
[0.6.0]: https://github.com/aicers/giganto/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/aicers/giganto/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/aicers/giganto/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/aicers/giganto/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/aicers/giganto/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/aicers/giganto/tree/0.1.0
