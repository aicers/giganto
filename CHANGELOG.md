# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add protocol compatibility check communication with connected Programs.
- Accepts QUIC connections from subscribers.
- GraphQL API supports cursor-based pagination.
- GraphQL API takes `start` and `end` parameters to specify the time range of
  the query.

### Fixed

- A query for a certain source no longer returns events from other sources.

## [0.1.0] - 2022-09-16

### Added

- Initial release.

[Unreleased]: https://github.com/aicers/giganto/compare/0.1.0...main
[0.1.0]: https://github.com/aicers/giganto/tree/0.1.0
