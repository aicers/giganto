# Giganto

Giganto is the raw-event storage system for AICE. It receives raw events through
QUIC channels and stores them in a database. It also provides a GraphQL API to
query the stored events.

[![Coverage Status](https://codecov.io/gh/aicers/giganto/branch/main/graph/badge.svg?token=AUUUIKX8O1)](https://codecov.io/gh/aicers/giganto)

## Usage

You can run giganto by invoking the following command:

```sh
giganto <path to config file>
```

In the config file, you can specify the following options:

```toml
key = "key.pem"                            # path to private key file
cert = "cert.pem"                          # path to certificate file
roots = ["ca1.pem", "ca2.pem", "ca3.pem"]  # paths to CA certificate files
ingestion_address = "0.0.0.0:38370"        # address to listen for QUIC connections
data_dir = "tests/data"                    # path to directory to store data
retention = "100d"                         # retention period for data
```

By default, giganto reads the config file from the following directories:

* Linux: `$HOME/.config/giganto/config.toml`
* macOS: `$HOME/Library/Application Support/com.einsis.giganto/config.toml`

## Test

Run giganto with the prepared configuration file. (Settings to use the
certificate/key from the tests folder.)

```sh
cargo run -- tests/config.toml
```

To test one-time transmission for all record types, execute as follows.

```sh
cargo test send
```

To test one-time transmission for specific record types, execute as follows.

```sh
cargo test send_conn_info
cargo test send_dns_info
cargo test send_log_info
cargo test send_http_info
cargo test send_rdp_info
```

To test ack reception after multi-transmission, execute as follows.

```sh
cargo test ack_info
```

## License

Copyright 2022 EINSIS, Inc.

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
