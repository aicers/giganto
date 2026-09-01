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

## When the process exits while it was serving

Giganto supervises the ingest, publish, peer and retention subsystems. If
one of their entry tasks ends on its own, the node does not keep serving
without it: it runs its usual shutdown sequence and then exits with a
failure status, so a service manager configured to restart on failure
does.

- Look for `entry task ended abnormally` in the log. The record names the
  task (`name`), says whether it was seen while the node was serving or
  read back during shutdown (`phase`), classes what happened (`outcome`
  is `early_exit`, `error`, `panic` or `cancelled`), and gives how long
  the task had been running (`age`).
- The subsystem also logs its own cause where the failure happened, such
  as `Ingest subsystem terminated unexpectedly`. That line is what says
  why; the record above is what says which.
- `generation ended degraded` means something ended abnormally while the
  node was already shutting down. The shutdown still completed and a
  requested reboot or power off was still carried out, but the exit
  status reports the failure. A configuration reload is the exception:
  the node starts the next generation and only logs the failure.
