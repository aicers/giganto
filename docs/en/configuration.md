# Configuration

## Key Configuration Summary

- `ingest_srv_addr`: QUIC ingest server address, default `[::]:38370`
- `publish_srv_addr`: QUIC publish server address, default `[::]:38371`
- `graphql_srv_addr`: GraphQL server address, default `[::]:8443`
- `data_dir`: Event storage directory (required), must be created beforehand
- `export_dir`: Export file storage directory (required), no default
- `retention`: Data retention period, default `100d`
- `ack_transmission`: ACK transmission threshold, default `1024`
- `max_open_files`: RocksDB max open files, default `8000`
- `max_mb_of_level_base`: RocksDB Level 1 size base (MB), default `512`
- `num_of_thread`: DB background thread count, default `8`
- `max_subcompactions`: Number of sub-compactions, default `2`
- `compression`: Enable RocksDB compression, default `false`
- `peer_srv_addr`: Node-to-node communication address, no default
- `peers`: Connected cluster nodes, no default

## Single Node Configuration Example

```toml
ingest_srv_addr = "0.0.0.0:38370"
publish_srv_addr = "0.0.0.0:38371"
graphql_srv_addr = "0.0.0.0:8443"

data_dir = "/path/to/giganto/data"
export_dir = "/path/to/giganto/export"

retention = "100d"
max_open_files = 8000
max_mb_of_level_base = 512
num_of_thread = 8
max_subcompactions = 2
ack_transmission = 1024

compression = false
```

## Cluster Configuration Example

```toml
peer_srv_addr = "10.0.0.10:38383"
peers = [
  { addr = "10.0.0.11:38383", hostname = "giganto-node-2" },
  { addr = "10.0.0.12:38383", hostname = "giganto-node-3" }
]
```

P2P cluster mode is enabled **only when a valid `peer_srv_addr` is
configured**. `peers` addresses and hostnames should be defined
according to the actual operational network and certificate policies.

## Configuration Backup and Recovery

- When updating the configuration file, Giganto creates a backup named
  `<config>.toml.bak`.
- If the configuration file cannot be read at startup and a `.toml.bak`
  file exists, it attempts to restore it from the backup.

## Compression Configuration Considerations

- Compression settings are stored in the `COMPRESSION` metadata file
  within the DB directory (`data_dir`). If the current configuration
  does not match the metadata at startup, the server returns an error
  and refuses to start.
- The `compression` option cannot be changed for an existing database.
  To modify it, the database must be recreated.
