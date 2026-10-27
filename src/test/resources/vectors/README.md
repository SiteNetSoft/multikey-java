# Test vectors

Fetched 2026-10-26. Tests never hit the network.

- `atproto-spec-examples.json`: the example `did:key` strings (P-256 and K-256) from the AT Protocol cryptography
  spec, https://atproto.com/specs/cryptography (the same keys appear in `signature-fixtures.json`).
- `signature-fixtures.json`, `w3c_didkey_K256.json`, `w3c_didkey_P256.json`: copied from
  https://github.com/bluesky-social/atproto-interop-tests (`crypto/` folder, branch main). The w3c_didkey files
  are the W3C did:key test vectors as packaged by that repo.
- `signature-fixtures.json` drives `SignaturesTest.atprotoVectors` (valid low-S signatures accepted; high-S and
  DER-encoded signatures rejected).
- `rfc7638-example.json`: the RSA JWK and expected thumbprint from RFC 7638 section 3.1,
  https://www.rfc-editor.org/rfc/rfc7638 (fetched 2026-10-26).
- `pem-{p256,k256,ed25519}-{private,public}.pem`: throwaway test-only keys generated 2026-10-26 with OpenSSL 3.6.5
  (`openssl genpkey` with named curves, then `openssl pkey -pubout`); PKCS#8 `PRIVATE KEY` and SPKI `PUBLIC KEY`.
  They protect nothing.
