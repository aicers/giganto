# GraphQL

## mTLS Requirements

The server reads the CA certificates provided via `--ca-certs` and uses
them to verify client certificates. A connection is only established if
the client presents a valid certificate during the TLS handshake.

## Accessing GraphQL Playground

The Playground is included as part of the GraphQL server routes.
Because the server requires mTLS, the browser must also present a
client certificate.

The GraphQL Playground is available at `https://<HOST>:<PORT>/graphql/playground`.
