# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [0.12.1] - 2023-06-26

### Added

- Supports the TLS protocol.
- Added migration functionality in `0.12.0`. This feature adds values for new fields
  (`orig_filenames`, `orig_mime_types`, `resp_filenames`, `resp_mime_types`) to
  `http raw event` in versions 0.12.0 and earlier.

## [0.12.0] - 2023-06-20

### Added

- added Giganto clustering funtionality. This feature connects giganto peer-to-peer,
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

- Change field name `duration` to `last_time`.  (Except Conn struct)
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
