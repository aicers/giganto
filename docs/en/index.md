# Overview

Giganto is a raw-event storage system. It receives events through QUIC
channels and provides a GraphQL API for querying stored data.

## Key Features

- Collects and stores raw events received from collectors via QUIC channels
- Provides a GraphQL API
- Supports single-node (standalone) mode
- Supports multi-node cluster mode
  - A cluster consists of multiple Giganto nodes communicating with each
    other and operating together as a single service.

## Security Assumption (mTLS)

The Giganto GraphQL server assumes that **mTLS (Mutual TLS with client
certificates)** is used.

Therefore, access to `/graphql` and `/graphql/playground` requires a
**client certificate**, and the server verifies client certificates using
the `--ca-certs` option provided at startup.

## Manual Map

- **Preparation before installation**: Prepare the required certificates,
  keys, CA files, and the `data_dir` directory.
- **Configuration**: Configure the service addresses, storage path, and
  data retention period. If using multiple nodes, configure the cluster
  settings according to your environment.
- **Operations**: Start Giganto using the configuration file and
  certificates, and verify the logs and mTLS connectivity.
- **GraphQL**: Provides filtering and pagination for search, export,
  and statistical analysis, and supports operational control
  through mutations such as `updateConfig`, `stop`, `reboot`, and
  `shutdown`.
- **Troubleshooting**: Common issues and recovery steps.

## Quick Start

1. Create the `data_dir` directory
2. Write the `config.toml` configuration file
3. Start Giganto
4. Authenticate using an mTLS client certificate and connect to
   `https://<HOST>:<PORT>/graphql/playground`
5. Review and modify the GraphQL queries.
