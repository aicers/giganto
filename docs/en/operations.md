# Operations

## Execution Command

Giganto is started using the following command.

```bash
giganto -c <CONFIG_PATH> --cert <CERT_PATH> --key <KEY_PATH> --ca-certs \
<CA_CERT_PATH>[,<CA_CERT_PATH>,...]
```

- `-c <CONFIG_PATH>`: TOML configuration file path (required)
- `--cert <CERT_PATH>`: Server certificate (PEM) (required)
- `--key <KEY_PATH>`: Server private key (PEM) (required)
- `--ca-certs <CA_CERT_PATH>[,...]`: CA certificates (PEM) for verifying
  client certificates (required)

`--ca-certs` Input Method

- Multiple CA certificates can be provided either as a comma-separated
  list or by repeating the `--ca-certs` option.

Logging

- Logs are written to standard output.
- `RUST_LOG` sets the level; the default is `info`.
- Under the systemd journal (standard output or standard error connected to
  it, as `JOURNAL_STREAM` names), each event is one line that starts with its
  syslog priority (`<3>` error, `<4>` warning, `<6>` info, `<7>` debug and
  trace), without a timestamp or colour codes, with line breaks inside an event
  written as `\n`. A panic is logged as one error entry.
- Elsewhere, colour codes are written only to a terminal.
- `--log-path` was removed; a command line that passes it is refused at
  startup.

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

Giganto does not rotate its certificates itself. An operator replaces
the files on disk and sends `SIGHUP`, and Giganto supports that being
done as often as once an hour. A reload rereads whichever files are
current when it runs, so repeated signals collapse into one reload and
nothing is lost by sending more of them than needed.

On `SIGHUP`, Giganto re-reads the certificate, private key, and CA
files from disk and delivers the refreshed material to the peer
subsystem, which applies it with the following observable behavior:

- After a successful reload, new inbound peer handshakes and later
  outbound reconnect attempts observe the refreshed peer TLS material.
- If the refreshed material cannot be applied — for example, because
  the certificate and private key do not form a valid pair — the
  previous peer TLS state is kept. The failure is logged and the peer
  subsystem keeps running on the previously installed material.

Long-lived connection policy:

- **Accepted peer-server connections** that were established before
  the reload keep running on their original TLS state until they are
  naturally closed or replaced. New inbound peer handshakes after the
  reload observe the refreshed server leaf certificate.
- **Outbound peer-client connections** that were already established
  keep running on their original TLS state as well. Subsequent
  reconnect attempts dial using the refreshed peer client
  configuration and observe the refreshed leaf certificate.
