# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2022-10-04

### Added

- limit Maximum request page size. (Requests over 100 will be treated as 100)
- Check protocol compatibility with connected Programs.
- Accepts QUIC connections from subscribers.
- GraphQL API supports cursor-based pagination.

### Changed

- `dnsRawEvents` takes `start` and `end` parameters to specify the time range
  of the query.

### Fixed

- A query for a certain source no longer returns events from other sources.

## [0.1.0] - 2022-09-16

### Added

- Initial release.

[0.2.0]: https://github.com/aicers/giganto/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/aicers/giganto/tree/0.1.0
