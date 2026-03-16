# Prerequisites

## Requirements

- Server certificate, private key, and trusted CA certificate (PEM format)
- The `data_dir` must be created beforehand.
- The `export_dir` is automatically created if the directory does not
  exist at the specified path.

## Network and Security Preparation

Giganto’s GraphQL server runs over HTTPS and requires mutual TLS (mTLS)
client authentication. Therefore, starting the server alone is not
sufficient—the client must also be configured with a certificate,
private key, and trusted CA.

## Certificate Preparation Guidelines

- A server certificate and private key are required.
- Clients accessing the GraphQL API must also provide an mTLS client
  certificate.
- CA certificates are provided via the `--ca-certs` option.
- Multiple CA certificates can be specified either as a comma-separated
  list or by repeating the `--ca-certs` option.
