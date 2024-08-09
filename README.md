# Giganto: Raw-Event Storage System for AICE

Giganto is a high-performance raw-event storage system, specifically designed
for AICE. It is optimized to receive and store raw events through QUIC channels
and provides a flexible GraphQL API for querying the stored events. Giganto
empowers AICE with the ability to efficiently handle large-scale data
processing and real-time analytics.

[![Coverage Status](https://codecov.io/gh/aicers/giganto/branch/main/graph/badge.svg?token=AUUUIKX8O1)](https://codecov.io/gh/aicers/giganto)

## Features

* Scalable Storage: Giganto provides a scalable and distributed storage system,
  optimized for handling raw events generated by AICE sensors.
* GraphQL API: Giganto offers a powerful and flexible GraphQL API, enabling
  developers to query stored events with ease.
* QUIC Channels: Giganto utilizes the QUIC protocol to enable fast, low-latency
  communication and data transfer.
* High Performance: Giganto is designed to efficiently handle high volumes of
  data, ensuring optimal performance for AICE.

## Usage

You can run giganto by invoking the following command:

```sh
giganto --cert <CERT_PATH> --key <KEY_PATH> --ca-certs <CA_CERT_PATH> \
--ca-certs <CA_CERT_PATH>
```

If you want to run giganto with local configuration file,

```sh
giganto -c <CONFIG_PATH> --cert <CERT_PATH> --key <KEY_PATH> --ca-certs \
<CA_CERT_PATH> --ca-certs <CA_CERT_PATH>
```

In the config file, you can specify the following options:

```toml
ingest_srv_addr = "0.0.0.0:38370"          # address to listen for ingest QUIC.
publish_srv_addr = "0.0.0.0:38371"         # address to listen for publish QUIC.
graphql_srv_addr = "127.0.0.1:8442"        # giganto's graphql address.
data_dir = "tests/data"                    # path to directory to store data.
retention = "100d"                         # retention period for data.
log_dir = "/data/logs/apps"                # path to giganto's syslog file.
export_dir = "tests/export"                # path to giganto's export file.
max_open_files = 8000                      # db options max open files.
max_mb_of_level_base = 512                 # db options max MB of rocksDB Level 1.
num_of_thread = 8                          # db options for background thread.
max_sub_compactions = 2                    # db options for sub-compaction.
ack_transmission = 1024                    # ack count for ingestion data.
addr_to_peers = "10.10.11.1:38383"          # address to listen for peers QUIC.
peers = [ { addr = "10.10.12.1:38383", hostname = "ai" } ]     # list of peer info.
```

By default, giganto reads the config file from the following directories:

* Linux: `$HOME/.config/giganto/config.toml`
* macOS: `$HOME/Library/Application Support/com.einsis.giganto/config.toml`

For the `max_mb_of_level_base`, the last level has 100,000 times capacity,
and it is about 90% of total capacity. Therefore, about `db_total_mb / 111111` is
appropriate.
For example, `90`MB or less for 10TB Database, `900`MB or less for 100TB would
be appropriate.

These values assume you've used all the way up to level 6, so the actual values may
change if you want to grow your data further at the level base.
So if it's less than `512`MB, it's recommended to set default value of `512`MB.

If there is no `addr_to_peers` option in the configuration file, it runs in
standalone mode, and if there is, it runs in cluster mode for P2P.

## Test

Run giganto with the prepared configuration file. (Settings to use the
certificate/key from the tests folder.)

```sh
cargo run -- -c tests/config.toml --cert tests/certs/node1/cert.pem \
--key tests/certs/node1/key.pem --ca-certs tests/certs/ca_cert.pem
```

## License

Copyright 2022-2024 ClumL Inc.

Licensed under [Apache License, Version 2.0][apache-license] (the "License");
you may not use this crate except in compliance with the License.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See [LICENSE](LICENSE) for
the specific language governing permissions and limitations under the License.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the [Apache-2.0
license][apache-license], shall be licensed as above, without any additional
terms or conditions.

[apache-license]: http://www.apache.org/licenses/LICENSE-2.0
