# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Support periodic time series.
- GraphQL API supports filtering with source name, kind name of log, time range,
  IP address range, port range.
- Publish check protocol compatibility with connected Programs.
- Publish support log/period time series record data request/response through QUIC.
- Add Packets Request GraphQL API.

### Changed

- GraphQL API now accepts `filter`, which includes the source name, time range,
  IP address ranges, and port ranges.
- GraphQL API returns readable log data

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

[Unreleased]: https://github.com/aicers/giganto/compare/0.2.0...main
[0.2.0]: https://github.com/aicers/giganto/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/aicers/giganto/tree/0.1.0
