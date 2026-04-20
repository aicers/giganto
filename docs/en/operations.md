# Operations

## Execution Command

Giganto is started using the following command.

```bash
giganto -c <CONFIG_PATH> --cert <CERT_PATH> --key <KEY_PATH> --ca-certs \
<CA_CERT_PATH>[,<CA_CERT_PATH>,...] [--log-path <LOG_PATH>]
```

- `-c <CONFIG_PATH>`: TOML configuration file path (required)
- `--cert <CERT_PATH>`: Server certificate (PEM) (required)
- `--key <KEY_PATH>`: Server private key (PEM) (required)
- `--ca-certs <CA_CERT_PATH>[,...]`: CA certificates (PEM) for verifying
  client certificates (required)
- `--log-path <LOG_PATH>`: Log file path (optional)

`--ca-certs` Input Method

- Multiple CA certificates can be provided either as a comma-separated
  list or by repeating the `--ca-certs` option.

`--log-path` Behavior

- Not specified: logs are written to `stdout`
- Specified and writable: logs are written to the specified file
- Specified but not writable: Giganto terminates
- Logs generated before tracing initialization may be written directly to
  stdout or stderr.

## Basic Execution

```bash
giganto -c /path/to/giganto/config.toml \
  --cert /path/to/giganto/certs/cert.pem \
  --key /path/to/giganto/certs/key.pem \
  --ca-certs /path/to/giganto/certs/ca_cert.pem
```

## Using Multiple CA Certificates

If multiple CA certificates need to be trusted, one of the following
methods can be used.

```bash
# Comma-separated
giganto -c /path/to/giganto/config.toml \
  --cert /path/to/giganto/certs/cert.pem \
  --key /path/to/giganto/certs/key.pem \
  --ca-certs /path/to/giganto/certs/ca1.pem,/path/to/giganto/certs/ca2.pem

# Repeating the argument
giganto -c /path/to/giganto/config.toml \
  --cert /path/to/giganto/certs/server.crt \
  --key /path/to/giganto/certs/server.key \
  --ca-certs /path/to/giganto/certs/ca1.pem \
  --ca-certs /path/to/giganto/certs/ca2.pem
```

## Items to Check After Startup

- Verify that the process does not exit immediately.
- Verify that the GraphQL server startup message appears in the logs.

## Peer Subsystem TLS Reload

On `SIGHUP`, Giganto re-reads the certificate, private key, and CA
files from disk and fans the refreshed material out to each subsystem.
The peer subsystem reacts to this signal with an atomic prepare/apply
cycle:

- Fresh peer server and peer client TLS configurations are built from
  the new material first.
- Only if both builds succeed are they installed together: the peer
  server endpoint swaps to the new server configuration, and the peer
  client configuration slot is replaced with the new one.
- If either build fails, the swap is aborted and the previous peer TLS
  state is preserved. The failure is logged and the peer subsystem
  keeps running on the old material.

Long-lived connection policy:

- **Accepted peer-server connections** that were established before
  the reload keep running on their original TLS state until they are
  naturally closed or replaced. New inbound peer handshakes after the
  reload observe the new server leaf certificate.
- **Outbound peer-client connections** that were already established
  keep running on their original TLS state as well. Subsequent
  reconnect attempts dial using the refreshed peer client
  configuration and observe the new leaf certificate.
