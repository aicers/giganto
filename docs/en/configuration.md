# Configuration

## Key Configuration Summary

- `ingest_srv_addr`: QUIC ingest server address, default `[::]:38370`
- `publish_srv_addr`: QUIC publish server address, default `[::]:38371`
- `graphql_srv_addr`: GraphQL server address, default `[::]:8443`
- `data_dir`: Event storage directory (optional, default: `data`). Giganto creates
  it at startup when omitted; an explicit directory must already exist.
- `export_dir`: Export file storage directory (optional, default: `export`),
  created on the first export.
- `retention`: Data retention period, default `100d`, at most `3650d` (write
  it in days; `10y` is longer)
- `oplog_retention`: Retention period for operation logs (OpLog), default
  `365d`, from `1d` to `3650d`. Other data uses `retention`.
- `ack_transmission`: ACK transmission threshold, default `1024`
- `max_open_files`: RocksDB max open files, default `8000`
- `max_mb_of_level_base`: RocksDB Level 1 size base (MB), default `512`
- `num_of_thread`: DB background thread count, default `8`
- `max_subcompactions`: Number of sub-compactions, default `2`
- `compression`: Enable RocksDB compression, default `false`
- `web_shutdown_timeout`: Graceful-shutdown budget for the HTTPS GraphQL server.
  When shutdown begins the server stops accepting new requests and waits up to
  this duration for already-accepted requests to finish before terminating any
  still in flight, default `30s`
- `drain_report_interval`: How often a shutdown drain reports that tasks are
  still running. It is a reporting cadence, not a timeout: the drain waits for
  every task however long it takes, and this only decides how often a shutdown
  that is still waiting says so. Must be greater than zero, default `5s`
- `peer_srv_addr`: Node-to-node communication address, no default. For other
  nodes to send this node GraphQL requests, it must be a specific address, not
  `0.0.0.0` or `[::]`
- `peers`: Connected cluster nodes, no default
- `endpoint_srv_addr`: Address of the endpoint entry, the TCP port Clumit
  Endpoint sends host telemetry to, no default. When the key is absent the entry
  is not opened; an empty value is a configuration error. See
  [Endpoint Entry](#endpoint-entry)

When disk usage exceeds 95 %, the retention task shortens both retention periods
by one day at a time until usage falls under 85 % or no more data can be
deleted.

Relative `data_dir` and `export_dir` paths resolve against the process's working
directory.

Saving a changed configuration through `updateConfig` writes `data_dir` to the
configuration file, even when it was originally omitted. It then counts as an
explicit path and must already exist on subsequent starts.

The RocksDB validity ranges on 64-bit targets are `max_open_files = 20..=C`,
`max_mb_of_level_base = 1..=262144`, `num_of_thread = 1..=128`, and
`max_subcompactions = 1..=8`. C is `max(20, min(soft RLIMIT_NOFILE, i32::MAX))`,
using the process soft open-file limit read once at startup; if reading it fails,
C is `4194304`. The thread caps are product policy limits. These ranges are
validity limits, not tuning recommendations.

At startup, out-of-range TOML values are clamped to the nearest bound, except
`max_open_files = -1`, which becomes C. One WARN per changed field reports the
file value, selected value, and valid range. The TOML is unchanged; RocksDB,
`--repair`, and the `config` query use the effective values. In-range values
are unchanged and produce no clamp warnings.

`updateConfig` rejects out-of-range values, including negative `max_open_files`,
without changing state or queuing the request. After an accepted update, a failure
in compression metadata validation, data directory migration, or database opening
logs an ERROR, restores the previous in-memory and persisted configuration, and
restarts with it once. The restore does not overwrite the update backup. If the
restore write fails, an ERROR asks that the file be checked and the previous
in-memory configuration still starts. A failure of that restored generation,
initial process startup, teardown, or startup after store opening is not recovered.
Check the effective outcome with the `config` query.

## Single Node Configuration Example

```toml
ingest_srv_addr = "0.0.0.0:38370"
publish_srv_addr = "0.0.0.0:38371"
graphql_srv_addr = "0.0.0.0:8443"

data_dir = "/path/to/giganto/data"
export_dir = "/path/to/giganto/export"

retention = "100d"
oplog_retention = "365d"
max_open_files = 8000
max_mb_of_level_base = 512
num_of_thread = 8
max_subcompactions = 2
ack_transmission = 1024

compression = false
web_shutdown_timeout = "30s"
drain_report_interval = "5s"
```

## Cluster Configuration Example

```toml
peer_srv_addr = "10.0.0.10:38383"
peers = [
  { addr = "10.0.0.11:38383", hostname = "001.giganto.node2.example.com" },
  { addr = "10.0.0.12:38383", hostname = "001.giganto.node3.example.com" }
]
```

P2P cluster mode is enabled **only when a valid `peer_srv_addr` is
configured**. `peers` addresses should be defined according to the actual
operational network. `peers[].hostname` is the peer certificate's SAN DNS name;
Giganto verifies the peer's certificate against it when connecting.

`peers[].hostname`, or the name a peer advertised when it connected, is also
the name Giganto sends that peer's GraphQL requests to and verifies its
certificate against. The address comes from the name's recorded `addr`, and the
port is the peer's GraphQL port.

## Endpoint Entry

```toml
endpoint_srv_addr = "10.0.0.10:38372"
```

The endpoint entry is a TLS 1.3 port, separate from the module ports in both
code path and client verification. It offers only the `senta-telemetry/1` ALPN
protocol and the X25519MLKEM768 key exchange, and accepts the self-signed
certificate an endpoint presents.

Which endpoints may send telemetry is decided by the active list REview pushes
to every Giganto node, together with the node's entry ID, through GraphQL
(`endpointApplyActiveList`, `endpointConfirmActiveList` and
`endpointActiveListState`). Only REview may call these fields: a caller whose
client certificate names any other service, a peer Giganto included, is
refused.

- The node is ready once a full list has been applied and an entry ID is
  stored. Until then it closes every endpoint connection at its `hello`
  without answering.
- The list is kept in memory only. After a process restart the node is not
  ready until REview sends a full list again, although the entry ID, which is
  stored in the database, survives. A restart of the services, such as after a
  configuration update, keeps the list.
- An endpoint is judged when it says `hello`. A listed, active endpoint gets
  the entry ID in its `hello_ack`. An endpoint that is not listed, or whose
  license is pending, gets `not_listed`; a suspended one gets `suspended`; and
  when the lease has expired every endpoint gets `lease_expired`. Each error
  is sent instead of `hello_ack`, and the connection is then closed.
- The list is held under a 30-minute lease, which REview extends by
  confirming the version applied; a full list extends it too. When the lease
  expires, every open endpoint connection is sent `lease_expired` and closed.
- An update that suspends or removes an endpoint's entry sends its open
  connection the new standing's error and closes it. An update that changes
  the entry ID closes every endpoint connection; reconnecting endpoints get
  the new entry ID.

Endpoints trust only the root CA, while the `--cert` file holds only the node's
leaf certificate. On this port, and only here, Giganto therefore presents the
leaf followed by the intermediate that issued it, taken from the `--ca-certs`
files. The intermediate is the certificate whose subject is the leaf's issuer
and whose Subject Key Identifier is the leaf's Authority Key Identifier; when
the bundle holds two CA generations with the same names, the one whose key
verifies the leaf's signature is chosen. A self-signed match is not an
intermediate. The module ports present the `--cert` file as is.

- At startup with `endpoint_srv_addr` set, no matching intermediate is a
  configuration error and Giganto exits.
- On SIGHUP, the intermediate is chosen again from the reloaded files, and new
  endpoint connections use the new chain and key; established ones are kept. If
  no intermediate matches, the endpoint port keeps its previous certificate
  chain and private key and an error is logged, while the module ports still
  take up the new files.
- When a configuration update restarts the services, the intermediate is chosen
  again. If none matches, the endpoint port keeps the chain and key it last
  used; if it has never had one, it stays closed until the next restart, and an
  error is logged. Adding, changing or removing `endpoint_srv_addr` through
  `updateConfig` opens, moves or closes the port on that restart.

## Certificate Requirements

Every certificate Giganto handles — its own, cluster peers', and ingest and
publish clients' — must carry a SAN DNS name of the form
`<instance>.<service>.<host>.<domain>` (for example,
`001.giganto.node1.example.com`). Giganto derives sensor names, node names, and
peer identities from this SAN, and rejects a certificate that does not carry
one; a `<service>@<host>` common name alone is not accepted. Bootroot issues
such certificates in production. For tests, static certificates from any CA
work as long as they carry the SAN.

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
