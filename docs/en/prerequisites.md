# Prerequisites

## Requirements

- Server certificate, private key, and trusted CA certificate (PEM format)
- An explicitly configured `data_dir` must be created beforehand. When omitted,
  the default `data` directory is created at startup.
- The `export_dir` is automatically created if the directory does not
  exist at the specified path.

## Network and Security Preparation

Giganto’s GraphQL server runs over HTTPS and requires mutual TLS (mTLS)
client authentication. Therefore, starting the server alone is not
sufficient—the client must also be configured with a certificate,
private key, and trusted CA.

The ingest, publish, peer and GraphQL servers accept only TLS 1.3 with the
hybrid post-quantum key exchange X25519MLKEM768. Every client must offer it:
sensors and other ingest and publish clients, GraphQL clients, and cluster
peers. A client that does not is refused at the handshake, and Giganto logs
the refusal at WARN as `TLS handshake from <address> failed: <error>`.

## Certificate Preparation Guidelines

- A server certificate and private key are required.
- Giganto's own certificate, and those of cluster peers and ingest and publish
  clients, must carry a SAN DNS name of the form
  `<instance>.<service>.<host>.<domain>`. See "Certificate Requirements" in
  the configuration guide.
- Clients accessing the GraphQL API must also provide an mTLS client
  certificate.
- CA certificates are provided via the `--ca-certs` option.
- Multiple CA certificates can be specified either as a comma-separated
  list or by repeating the `--ca-certs` option.
