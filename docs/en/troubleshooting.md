# Troubleshooting

## When the process does not start

- Verify that the `data_dir` directory actually exists.
- Verify that the paths for the certificate, private key, and CA
  certificate are correct.
- If a log path is specified, verify that the file has write permission.

## When GraphQL cannot be accessed

- Verify that the client is presenting a client certificate.
- The `--ca-certs` option provided when starting the server is used to
  verify client certificates, so verify that the certificate chain matches.

## When the cluster does not connect properly

- Verify that the `peer_srv_addr` and `peers` values match the actual
  network configuration.
- Check firewall policies and routing between peer nodes.
- Verify that the node certificates and hostname policies meet the
  mutual verification requirements.
