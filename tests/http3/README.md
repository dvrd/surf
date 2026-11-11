`localhost.pem` is a synthetic self-signed localhost/127.0.0.1 server certificate
for owned loopback tests. Its test-only RSA key is the existing
`http/v3/testdata/rsa2048.pem` fixture. It is never selected implicitly by a
production client or listener; the test explicitly installs its identity and
trust root. Do not use this identity outside tests.

The certificate was generated with `openssl req -new -x509`, the fixture key,
CN=localhost, SAN=DNS:localhost,IP:127.0.0.1, serverAuth EKU, digitalSignature key
usage, CA:FALSE and a3650-day validity period. The HTTP/3 implementation currently
accepts RSA identities in its TLS credential store, so the HTTP/2 helper's EC
identity cannot serve this fixture.
