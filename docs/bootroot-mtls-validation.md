# Bootroot mTLS Validation Environment for Data-Store

This document defines the shared validation environment that downstream
repositories can reuse when they need a runnable `data-store` server for
Bootroot mTLS end-to-end validation.

The goal of this setup is not to replace each repository's own integration
tests. Instead, this repository provides a repeatable way to:

- start `data-store` with certificate, key, and CA bundle inputs that match the
  Bootroot file layout expectations
- verify that the GraphQL endpoint requires client certificates
- give downstream repositories one common server-side setup so they do not have
  to redefine it in every issue

## What This Repository Provides

- a reusable helper script:
  `./scripts/bootroot-mtls-validation.sh`
- locally generated CA, server, and client certificates for validation
- Bootroot-style DNS SAN fixtures for both the server and the client
- a multi-PEM CA bundle that downstream repositories can reuse as-is
- a generated local config and runtime directory under
  `/tmp/giganto-bootroot-mtls` by default

## Fixture Layout

By default the helper script generates a fresh local certificate set under
`/tmp/giganto-bootroot-mtls/certs`.

- server certificate:
  `/tmp/giganto-bootroot-mtls/certs/server.cert.pem`
- server private key:
  `/tmp/giganto-bootroot-mtls/certs/server.key.pem`
- client certificate:
  `/tmp/giganto-bootroot-mtls/certs/client.cert.pem`
- client private key:
  `/tmp/giganto-bootroot-mtls/certs/client.key.pem`
- root CA certificate:
  `/tmp/giganto-bootroot-mtls/certs/ca.root.pem`
- extra CA certificate:
  `/tmp/giganto-bootroot-mtls/certs/ca.extra.pem`
- CA bundle:
  `/tmp/giganto-bootroot-mtls/certs/ca.cert.pem`

These generated files are not Bootroot-issued certificates. They are a local
stand-in for the same input shape and naming model:

- leaf certificate file
- private key file
- CA bundle file
- Bootroot-style DNS SAN identity

If needed, callers can still override the generated files with their own local
certificate inputs through environment variables.

The generated server certificate includes both:

- local validation SANs such as `localhost` and `127.0.0.1`
- a Bootroot-style DNS SAN:
  `validation.data-store.localhost.bootroot.test`

The generated client certificate includes a Bootroot-style DNS SAN:

- `validation.sensor.localhost.bootroot.test`

The generated CA bundle contains multiple PEM certificates so downstream
repositories can validate multi-PEM handling instead of a single-cert shortcut.

This means the generated fixtures are useful for shape-compatible validation,
but they do not prove that the exact certificate material issued by Bootroot is
accepted end-to-end. Real Bootroot certificate validation still needs to be run
separately.

The generated bundle order is intentional:

- the first PEM is an unrelated root CA
- the second PEM is the CA that actually signs both generated leaf certs

Because of that, any client or server implementation that incorrectly loads
only the first certificate from the bundle should fail the documented workflow.

## Important Prerequisite

The happy-path commands below assume the `data-store` runtime already includes
the Bootroot identity acceptance change tracked in `aicers/giganto#1555`.

Without `#1555`, Bootroot-style DNS SAN fixtures can still fail at runtime with
`the subject of the certificate is not valid`, even if the certificate and CA
bundle shapes are otherwise correct.

## Validation Workflow

### 1. Prepare a local validation directory

```sh
./scripts/bootroot-mtls-validation.sh prepare
```

This creates:

- a generated config file
- a generated local CA, server certificate, and client certificate
- writable data and export directories
- a writable log directory

By default the generated files live under `/tmp/giganto-bootroot-mtls`.

### 2. Start the data-store server

```sh
./scripts/bootroot-mtls-validation.sh run-server
```

This starts `giganto` with:

- the generated config file
- the local server certificate and key
- the local CA bundle

Use a build that already includes `giganto#1555` if you expect the generated
Bootroot-style DNS SAN fixture to succeed end-to-end.

Default addresses:

- GraphQL: `127.0.0.1:18443`
- ingest: `127.0.0.1:18370`
- publish: `127.0.0.1:18371`

### 3. Verify the mTLS GraphQL endpoint

In another terminal:

```sh
./scripts/bootroot-mtls-validation.sh query-config
```

This sends a GraphQL request with the client certificate fixture and prints the
JSON response. A successful response confirms that:

- the server started with the expected certificate inputs
- the server trusts the configured multi-PEM CA bundle beyond the first PEM
- the GraphQL endpoint accepts a client certificate signed by that CA

### 4. Reuse the same server from downstream repositories

Downstream repositories should treat this environment as the shared
`data-store` side of the validation.

They can then record their own repository-specific end-to-end results against:

- GraphQL address: `https://127.0.0.1:18443/graphql`
- CA bundle: `/tmp/giganto-bootroot-mtls/certs/ca.cert.pem`

## Real Bootroot Certificate Validation

When you want to confirm compatibility with actual Bootroot-issued inputs
instead of locally generated stand-ins, override the fixture paths with real
certificate material.

Required inputs:

- server cert
- server key
- client cert
- client key
- CA bundle

Example:

```sh
export BOOTROOT_GIGANTO_SERVER_CERT=/path/to/bootroot/server.cert.pem
export BOOTROOT_GIGANTO_SERVER_KEY=/path/to/bootroot/server.key.pem
export BOOTROOT_GIGANTO_CLIENT_CERT=/path/to/bootroot/client.cert.pem
export BOOTROOT_GIGANTO_CLIENT_KEY=/path/to/bootroot/client.key.pem
export BOOTROOT_GIGANTO_CA_CERTS=/path/to/bootroot/ca_bundle.pem
```

Two-terminal workflow:

```sh
./scripts/bootroot-mtls-validation.sh run-server-real
```

In another terminal:

```sh
./scripts/bootroot-mtls-validation.sh query-config-real
```

One-command smoke check:

```sh
./scripts/bootroot-mtls-validation.sh smoke-real
```

`smoke-real` starts `data-store` with the provided real certificate inputs,
waits for the GraphQL endpoint to come up, runs the same mTLS query, prints the
response, and stops the temporary server process.

If you need longer startup time, increase the timeout:

```sh
export BOOTROOT_SMOKE_TIMEOUT_SECS=120
./scripts/bootroot-mtls-validation.sh smoke-real
```

## Environment Variables

The helper script supports overriding the defaults.

- `BOOTROOT_VALIDATION_DIR`
- `BOOTROOT_GIGANTO_GRAPHQL_ADDR`
- `BOOTROOT_GIGANTO_INGEST_ADDR`
- `BOOTROOT_GIGANTO_PUBLISH_ADDR`
- `BOOTROOT_GIGANTO_CA_KEY`
- `BOOTROOT_GIGANTO_ROOT_CA_CERT`
- `BOOTROOT_GIGANTO_EXTRA_CA_KEY`
- `BOOTROOT_GIGANTO_EXTRA_CA_CERT`
- `BOOTROOT_GIGANTO_SERVER_CERT`
- `BOOTROOT_GIGANTO_SERVER_KEY`
- `BOOTROOT_GIGANTO_CLIENT_CERT`
- `BOOTROOT_GIGANTO_CLIENT_KEY`
- `BOOTROOT_GIGANTO_CA_CERTS`
- `BOOTROOT_SMOKE_TIMEOUT_SECS`

Use these if a downstream repository needs different ports or wants to point at
different local fixture files.

## Downstream Usage Notes

This repository provides the shared `data-store` side of the validation. The
client-side Bootroot compatibility work still belongs to each downstream
repository, and repository-specific status tracking should live in issue notes
or review documents rather than in this runbook.

One important prerequisite is that the `data-store` runtime used for validation
must include the Bootroot identity acceptance change tracked in
`aicers/giganto#1555`. Without that change, Bootroot-style DNS SAN fixtures can
still fail at runtime with `the subject of the certificate is not valid`.

## Known Gaps and Downstream Prerequisites

- This repository only prepares the shared `data-store` side of the validation.
- Each downstream repository still needs its own client-side Bootroot
  compatibility work.
- Each downstream repository should keep its own integration tests and record
  its own end-to-end validation procedure and results in its issue.
- This setup validates the mTLS endpoint and reusable server startup procedure.
  It does not automatically orchestrate other repository binaries.
- The helper script requires `openssl` and `curl` to be installed locally.
