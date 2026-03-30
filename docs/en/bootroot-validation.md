# Bootroot mTLS Validation Runbook

This document describes the shared validation environment for
Bootroot-style mTLS with Giganto (data-store). Downstream repositories
can reuse this setup to validate their client connections without
redefining the full environment each time.

Related issues:

- [aicers/giganto#1556][issue] — This issue (shared validation env)
- [aicers/giganto#1555][1555] — Bootroot mTLS prerequisite changes

[issue]: https://github.com/aicers/giganto/issues/1556
[1555]: https://github.com/aicers/giganto/issues/1555

## Overview

The validation environment provides:

- A canonical Bootroot-shaped certificate fixture with
  `leaf <- intermediate <- root`
- A CA bundle fixture containing `intermediate + root`
- Scripts to generate fixtures, start the server, and run a
  smoke check
- Support for both locally generated fixtures and real
  Bootroot-issued certificate overrides

## Prerequisites

- OpenSSL CLI (for fixture generation)
- curl (for smoke checks)
- A built Giganto binary (`cargo build --release`) or `giganto`
  in `PATH`
- **[aicers/giganto#1555][1555]**: Bootroot mTLS prerequisite
  changes must be merged for full CA bundle support

## Quick Start

All scripts are in `tools/bootroot-validation/`.

### 1. Generate Certificate Fixtures

```bash
cd tools/bootroot-validation
./generate-fixtures.sh
```

This creates the following in `checked-fixtures/`:

| File               | Description                              |
|--------------------|------------------------------------------|
| `root.pem`         | Root CA certificate                      |
| `root.key`         | Root CA private key                      |
| `intermediate.pem` | Intermediate CA certificate              |
| `intermediate.key` | Intermediate CA private key              |
| `leaf.pem`         | Leaf certificate (`CN=localhost`)        |
| `leaf.key`         | Leaf private key                         |
| `ca-bundle.pem`    | CA bundle (intermediate + root)          |

The chain models the Bootroot relationship:
`leaf <- intermediate <- root`.

The CA bundle concatenates `intermediate.pem` then `root.pem`.
**Order matters**: some TLS implementations expect the nearest
issuer first.

### 2. Start the Validation Server

```bash
# Generate fixtures if missing and start the server:
./start-validation.sh --generate

# Or start with pre-existing fixtures:
./start-validation.sh

# Start in background:
./start-validation.sh --generate --background
```

The server listens on `https://localhost:8443` by default.

### 3. Run the Smoke Check

In a separate terminal:

```bash
./smoke-check.sh
```

Expected output on success:

```text
=== Bootroot mTLS Smoke Check ===
...
HTTP status: 200
...
=== SMOKE CHECK PASSED ===
mTLS handshake succeeded and GraphQL endpoint responded.
```

## Using Real Bootroot Certificates

To validate with real Bootroot-issued certificates instead of
locally generated fixtures, set environment variables:

```bash
export REAL_BOOTROOT_LEAF_PEM=/path/to/real/leaf.pem
export REAL_BOOTROOT_KEY_PEM=/path/to/real/leaf.key
export REAL_BOOTROOT_CA_BUNDLE=/path/to/real/ca-bundle.pem

./start-validation.sh
# In another terminal:
./smoke-check.sh
```

Both `start-validation.sh` and `smoke-check.sh` honor these
overrides. When set, locally generated fixtures are ignored.

## Certificate Fixture Design

### Bootroot-style CA Bundle

The canonical CA bundle (`ca-bundle.pem`) contains:

1. **Intermediate CA certificate** (first)
2. **Root CA certificate** (second)

This order matches Bootroot semantics where the client or server
presents the nearest issuer first in the chain.

### Subject Fields

| Certificate    | CN                                 |
|----------------|------------------------------------|
| Root CA        | `Bootroot Test Root CA`            |
| Intermediate   | `Bootroot Test Intermediate CA`    |
| Leaf           | `localhost`                        |

All test certificates use `O=aicers, OU=giganto-test`.

The leaf certificate includes SAN entries:
`DNS:localhost, IP:127.0.0.1, IP:::1`.

### Backward-Compatible vs Bootroot-Style CA Input

| Check Type             | CA Input                          |
|------------------------|-----------------------------------|
| Backward-compatible    | Single root CA PEM file           |
| Bootroot-style         | CA bundle (intermediate + root)   |

**Backward-compatible**: Pass only the root CA to `--ca-certs`.
This works when the server certificate is directly signed by the
root CA (the existing `tests/certs/` setup).

```bash
giganto -c config.toml \
  --cert tests/certs/node1/cert.pem \
  --key tests/certs/node1/key.pem \
  --ca-certs tests/certs/ca_cert.pem
```

**Bootroot-style**: Pass the CA bundle (intermediate + root) to
`--ca-certs`. This is required when the leaf cert is signed by
an intermediate CA.

```bash
giganto -c config.toml \
  --cert checked-fixtures/leaf.pem \
  --key checked-fixtures/leaf.key \
  --ca-certs checked-fixtures/ca-bundle.pem
```

## Client Validation Matrix

The following clients connect to Giganto over mTLS. This table
tracks which combinations have been exercised with the shared
validation environment.

| Client                   | Protocol | Status      | Notes       |
|--------------------------|----------|-------------|-------------|
| time-series-generator    | QUIC     | Not yet     |             |
| semi-supervised engine   | QUIC     | Not yet     |             |
| sensor (piglet)          | QUIC     | Not yet     |             |
| data-broker (crusher)    | GraphQL  | Not yet     |             |

Downstream repositories should update their respective issues
with validation results after running the smoke check:

- [aicers/crusher#299](https://github.com/aicers/crusher/issues/299)
- [aicers/hog#1355](https://github.com/aicers/hog/issues/1355)
- [aicers/piglet#1688](https://github.com/aicers/piglet/issues/1688)
- [aicers/reproduce#826](https://github.com/aicers/reproduce/issues/826)

## Configuration Reference

### Environment Variables

| Variable                   | Default                        |
|----------------------------|--------------------------------|
| `REAL_BOOTROOT_LEAF_PEM`   | `checked-fixtures/leaf.pem`    |
| `REAL_BOOTROOT_KEY_PEM`    | `checked-fixtures/leaf.key`    |
| `REAL_BOOTROOT_CA_BUNDLE`  | `checked-fixtures/ca-bundle.pem` |
| `GIGANTO_BIN`              | Auto-detected                  |
| `GIGANTO_DATA_DIR`         | `/tmp/giganto-validation-data` |
| `GIGANTO_EXPORT_DIR`       | `/tmp/giganto-validation-export` |
| `GRAPHQL_SRV_ADDR`         | `[::]:8443`                    |

### Template Config

See `tools/bootroot-validation/data-store.env.template` for a
complete environment template that can be copied and customized.

## Troubleshooting

### TLS Handshake Failure

- Verify the CA bundle contains both intermediate and root certs
- Check certificate expiry: `openssl x509 -in leaf.pem -noout -dates`
- Verify chain: `openssl verify -CAfile root.pem -untrusted intermediate.pem leaf.pem`

### Wrong CA Bundle Order

The CA bundle must list intermediate before root. Recreate with:

```bash
cat intermediate.pem root.pem > ca-bundle.pem
```

### Certificate Expired

Regenerate fixtures:

```bash
./generate-fixtures.sh
```

Test fixtures are valid for 30 days.

### Client Certificate Rejected

Ensure the client certificate is signed by a CA in the server's
trust store. For Bootroot validation, the client cert must chain
to the same root CA through the intermediate.

## Cleanup

Remove generated fixtures:

```bash
./generate-fixtures.sh --clean
```

Remove validation data:

```bash
rm -rf /tmp/giganto-validation-data /tmp/giganto-validation-export
```

## Recording Downstream Results

When running the validation for a downstream repository issue:

1. Note the fixture set used (generated or real Bootroot)
2. Record the date of validation
3. Record which client was tested and the protocol used
4. Paste the smoke check output into the downstream issue
5. Note any repository-specific adjustments needed

## Known Gaps

- QUIC client validation (ingest/publish) requires building each
  client service. The smoke check only covers the GraphQL
  (HTTPS) endpoint.
- Real Bootroot certificates are not included. Use the
  `REAL_BOOTROOT_*` overrides when available.
- [aicers/giganto#1555][1555] must be merged for the CA bundle
  to be fully supported in all code paths.
