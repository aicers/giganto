# Test Certificates

These files let the README's "Run Giganto with the prepared configuration
file" command start Giganto without Bootroot. No test reads them.

- `ca_cert.pem`: a self-signed CA (`basicConstraints CA:TRUE`, `keyCertSign`).
- `node1/cert.pem`, `node1/key.pem`: a leaf signed by that CA, with the SAN
  `001.giganto.node1.example.test`, EKU `serverAuth,clientAuth`, and a PKCS#8
  key. Giganto uses it as both its server certificate and its peer client
  certificate.

Giganto reads its identity only from a SAN DNS name of the form
`<instance>.<service>.<host>.<domain>`, so any replacement must carry one.

## Regenerating

Run the following from this directory with OpenSSL 3.0 or later. The CA key is
deleted afterward; regenerating replaces the CA and the leaf together.

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc \
  -keyout ca_key.pem -out ca_cert.pem -days 3653 \
  -subj "/CN=Giganto Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc \
  -keyout node1/key.pem -out node1/cert.pem -days 3653 \
  -CA ca_cert.pem -CAkey ca_key.pem \
  -subj "/CN=001.giganto.node1.example.test" \
  -addext "subjectAltName=DNS:001.giganto.node1.example.test" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth,clientAuth"
rm ca_key.pem
```
