# Giganto

Giganto is the raw-event storage system for AICE.

## Usage

Before running the app, create a toml extension file and write it in the format below.

```toml
 key = "key.pem"
 cert = "cert.pem"
 roots = ["root_one.pem","root_two.pem","root_three.pem"]
 ingestion_address = "0.0.0.0:38370"
 data_dir = "tests/data"
```

* `key`: Giganto's key path.
* `cert`: Giganto's cert path.
* `roots`: RootCA's path of clients connected to Giganto.
* `ingestion_address`: Address of Gignato.
* `data_dir`: db storage path.

Build and serve the app with Cargo as follows:

```sh
cargo run [-- FLAGS | OPTION]
```

When you run the program, Giganto reads the config file from the default folder.

To run without giving the config file option, save the file to the path below.

```sh
"/Users/[username]/Library/Application Support/com.einsis.giganto/config.toml"
```

## FLAGS

* `-h`, `--help`: Prints help information
* `-V`, `--version`: Prints version information

## OPTION

* `config_file`: The path to the toml file containing server config info.

## TEST

Run giganto with the prepared configuration file.

(Settings to use the certificate/key from the tests folder.)

```sh
cargo run -- tests/config.toml
```

To run a test for all record types, run.

```sh
cargo test
```

To run a test for a specific record type, run one of the commands below.

```sh
cargo test send_conn_info
cargo test send_dns_info
cargo test send_log_info
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
