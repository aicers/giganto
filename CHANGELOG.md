# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added migration functionality in 0.19.0. This feature deletes the values
  of existing keys in netflow5/netflow9/seculog from versions prior to 0.19.0
  and inserts the values of new keys.

### Changed

- Modify the `sources` query to return results that also include
  sources from its peers.
- Changed the prefix of the `Netflow5`/`Netflow9`/`SecuLog` db key to source.
- Modify the related queries as the db key of `Netflow5`/`Netflow9`/`SecuLog`
  is changed to source.(`netflow5_raw_events`/`netflow9_raw_events`/
  `secu_log_raw_events`)

## [0.18.0] - 2024-02-16

### Changed

- Reverted the change of logging from `log-broker` to `tracing`.

### Fixed

- Fixed the default port to `8442`.

## [0.17.0] - 2024-01-24

### Added

- Added the ability to filter via `agent_id` in the filter of a GraphQL query
  requesting a sysmon events.
- Added `SmtpRawEvent` to the return value union of `network_raw_events` GraphQL
  query.
- Added `RunTimeIngestSources` type that checks for information from source
  that is connected to ingest in real time. This type is not currently used,
  but may be used in the future to provide real-time connection information.

### Changed

- Modify GraphQL schema file due to the addition of the `agent_id` field.
- Changed `PEER_VERSION_REQ` to ">=0.17.0,<0.18.0"
- Changed `PUBLISH_VERSION_REQ` to ">=0.17.0,<0.18.0"
- Modify `export` query to set the extension of the extract file according to
  the export type.

### Fixed

- Fix the part of the `export` query about validating filters for protocols.
- Fix to initialize `ingest_sources` value from `sources` cf on giganto startup.
  This change is intended to ensure that `IngestSources` provide all source
  information for stored data and `RunTimeIngestSources` provide real-time
  connection source information.

## [0.16.0] - 2024-01-08

### Added

- Added to call more flushes within the `handle_data` function of `ingest` that
  receive raw events. This change ensures that data is saved in all cases where the
  `handle_data` function terminates, such as when an `error` occurs.
- Added functionality to control the sending of acknowledgments.
  - Set the `ack transmission count` by reading from the config file.
  - Changed the type of ack transmission count checked in `ingest` from `const u16`
    to `AckTransmissionCount`(`Arc<RwLock<u16>>`).
  - Added `set_ack_transmission_count` GraphQL query to set the ack transmission
    count.This query changes the `AckTransmissionCount` used in ingest and
    `ack_transmission` in the config file to the input `count` value.
- Added documentation for implementing cluster-supported GraphQL APIs in
  `docs/guide-giganto-cluster-graphql.md`.
- Added `ConvertGraphQLEdgesNode` derive macro that implements `From` trait from
  GraphQL client structs to project structs.
- Supported `log-broker` to send/receive operation log with redis server.
  - Set the redis server with `redis_log_address`, `redis_log_agent_id` and
    `redis_log_fetch_interval` in configuration options.

### Changed

- Modify the `set_giganto_config` and `giganto_config` GraphQL queries to
  read/write the ack transmission count.
- Modify the `set_giganto_config` and `giganto_config` GraphQL queries so that
  the fields that take integers read/write the config file for their respective
  types.
- Modify the `giganto_config` query so that config files that work in standalone
  mode can also be read correctly.
- Changed `export` GraphQL query's response value format from `{export_path}` to
  `{export_path}@{giganto_node_name}`
- Changed logging from `tracing` to `log-broker`.
- Changed `PEER_VERSION_REQ` to ">=0.16.0,<0.17.0"
- Changed `PUBLISH_VERSION_REQ` to ">=0.16.0,<0.17.0"
- Added giganto cluster support for GraphQL and publish message requests.
- Added `request_from_peer: Option<bool>` argument to GraphQL endpoints:
  `netflow5_raw_events`, `netflow9_raw_events`, `secu_log_raw_events`,
  `statistics`.

### Fixed

- Fix `retain_periodically`

## [0.15.4] - 2023-11-22

### Added

- Added GraphQL query `sysmon_events` to retrieve all sysmon events at once.

### Changed

- Change to use the `batched_multi_get_cf` provided by rocksdb for multi get search.
  - Since `batched_multi_get_cf` is used, add the prefix `batched` to the
    `multi_get_from_ts`/`multi_get_with_source` functions respectively.
- Changed manual boundary check to boundary checking via `iterator_cf_opt`.
- Rename type aliases `PacketSources` to `PcapSources`, `Sources` to
  `IngestSources`, and `StreamDirectChannel` to `StreamDirectChannels`;
  And move their definition location from `ingest.rs` to `main.rs`.
- Modified `retain_periodically`
  - When disk usage exceeds `USAGE_THRESHOLD` delete old data until disk usage
    is reduced to `USAGE_LOW`.
  - Supports all column families.
  - The iterator stops processing data once it encounters data that is newer
    than the specified retention period.
- Moved `netflow` source to value from key.

## [0.15.3] - 2023-11-09

### Changed

- Changed `check_address` and `check_port` to have a close ended search where
  it will only return the events that contain the address or port for single
  input

## [0.15.2] - 2023-11-09

### Changed

- Change `MessageCode::RawData` request processing code to send raw events
  to REconverge in the same format as `MessageCode::RangeData`.

## [0.15.1] - 2023-11-08

### Changed

- Moved `secu_log` source to value from key.

## [0.15.0] - 2023-11-08

### Changed

- Updated giganto-client to 0.15.0
- Changed minimum/maximum version to 0.15.0 <= version < 0.16.0

## [0.14.0] - 2023-11-07

### Added

- Added `--repair` option to only fix the database problem then terminated.
- Support `NetflowV5`, `NetflowV9` events. These events does not streamed
  to Hog or Crusher.
- Support `Seculog` events.
  - In graphql, `Seculog` requires its kind.
    `wapples`, `mf2`, `sniper`, `aiwaf`, `tg`, `vforce`, `srx`, `sonicwall`
    `fgt`, `shadowwall`, `axgate`, `ubuntu`, `nginx`

### Changed

- Modified Kerberos event to support giganto-client.
- Changed `max_background_jobs` to 6 from 2.
- Changed minimum version to 0.13.1.

### Fixed

- Fix potential bug in `retain_periodically`

## [0.13.1] - 2023-09-18

### Changed

- Change the `statistics` Graphql Api.
  - Removed `core` as an argument to the query. Also changed the condition of
    source to allow searching for `multiple sources`.
  - Provides statistics data by `source`/`time`/`protocol`.
  - If the statistics data type is `statistics`, provide `bps`/`pps`.
  - If it's of type `network` (network-sourced events collected by `piglet`),
    provide `eps`.
  - If there is no value for the protocol field in the filter, statistics are
    provided for `all protocol`.
  - If filter has no value for the time field, it will provide the most `recent`
    statistics.
- Add feature to generate benchmark statistics for ingest events.
- Modify to execute flush when giganto down.

## [0.13.0] - 2023-08-28

### Added

- Add GraphQL query `statistics` to read data from `statistics` store.
  The result format is `Protocol/Size/Count`.
  - `Protocol`: target protocol name like `Statistics`, `Http`, `Dns`.
    `Statistics` is the input traffic statistics of the collector device.
  - `Size`: packet size for `Statistics` or 0 for other protocols.
  - `Count`: packet count for `Statistics` or event count for other protocols.
- Add key generation feature for intuitive data lookup of database in giganto.
  - `StorageKeyBuilder`: This is a builder structure for dynamically generating keys.
    Depending on whether you have 2 or 3 keys, call the `start`/`mid`/`end` function
    to set the keys.
  - `StorageKey`: A structure that stores lookup keys generated by `StorageKeyBuilder`.
  - `KeyExtractor`: A trait for calling the value to be set by the key.
- Supports 14 sysmon events.
- Added `search sysmon event` Graphql Api for `sysmon` supported by giganto.

### Changed

- Replaced `lazy_static` with the new `std::sync::OnceLock`.
- Modify `pcap_with_data` test function to compare times based on utc timezone.
- Change the key of `statistics` store to `source + core id + timestamp` not to
  overwrite statistics data from other core of same machine.
  When Giganto is loading with old DB version, the old data will be removed
  because it's possible to be overwritten by other core's data.
- Change `export` query to support `statistics` store.
  This change makes it possible to export statistics data of only core 0 of
  the collector device. This will be fixed in next change.
- Remove unused `time()` from `RawEventFilter` trait.
- Modify to use `Networkfilter` in `sysmon raw event` Graphql Api.
- Modify statistics migration version to 0.13.0 from 0.12.4.

### Fixed

- Fixed to only generate the `collect_records` error message when an error event
  exists, and applied the same change to `export`.
- Fixed to `export` query for export `statistic data` for all `cores`.

## [0.12.3] - 2023-07-10

### Changed

- Fixed fields of `FtpRawEvent`, `FtpJsonOutput`
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
- Added migration functionality in `0.12.0`. This feature adds values for new fields
  (`orig_filenames`, `orig_mime_types`, `resp_filenames`, `resp_mime_types`) to
  `http raw event` in versions 0.12.0 and earlier.

## [0.12.0] - 2023-06-20

### Added

- added Giganto clustering functionality. This feature connects giganto peer-to-peer,
  and connected gigantos share each other's `peer` list and connected `source` list.
- Supports the LDAP protocol.

### Changed

- Supports the expanded HTTP protocol.
- Modify `proto` field of `Ftp`, `Mqtt`, `Ldap` to u8 from u16.
- Modify the processing part of REconverge's data request.
  - Modify to handle network, log, and time series data requests with `ReqRange`
    and `RequestRange`.
  - Add to handle `Timeseries` requests in `MessageCode::RawData`.
  - Modify `multi_get_with_source` to return in the form of
    `Vec<(i64, String, Vec<u8>)>`.

## [0.11.0] - 2023-05-16

### Changed

- Modify the certificate verification.
- Update quinn to version 0.10 and rustls to version 0.21 for giganto-client
  version 0.7.0

## [0.10.2] - 2023-05-12

### Added

- Supports the MQTT protocol.
- Add `cfg path` fields to Settings. This path is used to fetch/modify
  giganto's config.

### Fixed

- Fixed to check for DB compatibility version.

## [0.10.1] - 2023-05-02

### Added

- Add event search GraphQL API for protocols supported by `giganto`.
  (`dns`, `conn`, `rdp`, `smtp`, `ntlm`, `kerberos`, `ssh`, `DceRpc`,`ftp`)

## [0.10.0] - 2023-04-28

### Added

- Add GIGANTO DB version compatibility check.
- Add a publish API to return the source, raw_events
  from the source, timestamps for REconverge.
- Supports the FTP protocol.
- Add a GraphQL API to search http events

## [0.9.0] - 2023-04-03

### Added

- Add GraphQL API to return source list.

### Changed

- Change the format of data sent to REconverge from the publish module. ([ref](https://github.com/aicers/giganto-client/issues/9))

## [0.8.0] - 2023-03-30

### Added

- Add Giganto Restart processing.
- Add more fields to `dns`, `conn`, `http`
- Add common fields to network events.
- Publish support Packet request/response through QUIC.
- Add Packet store.
- Add GraphQL API for Packet.
- Add database options to config file.
- Add GraphQL API for config file.

### Changed

- Change field name `duration` to `last_time`. (Except Conn struct)
- Modify to receive and process `multiple sources` of stream request messages
  from `HOG`.
- Modify module name `ingestion` to `ingest`.
- Create giganto's communication part as a separate crate. (giganto-client)
- Move init tracing to giganto-client crate for oplog logging.
- Fix packet logic in ingest.
- Rocksdb compression type has changed to Lz4, zstd from snappy
- Move giganto-client to separate repo [giganto-client](https://github.com/aicers/giganto-client).

## [0.7.0] - 2023-01-04

### Added

- Add export file to GraphQL API. (`csv`, `json` format support)
- Add `Statistics` column family. Receive and save traffic statistics from Piglet.
- Save Giganto's `syslog` to a path written to `log_dir` in configuration file.
- Add `Oplog` (Operation log)

### Changed

- Send different stream start message depending on the daemon.
- Check the write permission on `/data/logs/apps` directory.

## [0.6.0] - 2022-12-06

### Added

- Publish support protocol record data request/response through QUIC.
- Add periodic time series to GraphQL API.
- Add send `all` source network stream to hog.
- Add more network data types. (`Ntlm`, `Kerberos`, `Ssh`, `DceRpc`)

### Changed

- The key in timeseries data includes timestamp.
- Change DNS answer field to `Vec<String>`.

### Removed

- Remove send network stream to hog from database.

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

[Unreleased]: https://github.com/aicers/giganto/compare/0.18.0...main
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
