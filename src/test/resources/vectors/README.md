# Test vectors

Fetched 2026-10-26. Tests never hit the network.

- `atproto-spec-examples.json`: the example `did:key` strings (P-256 and K-256) from the AT Protocol cryptography
  spec, https://atproto.com/specs/cryptography (the same keys appear in `signature-fixtures.json`).
- `signature-fixtures.json`, `w3c_didkey_K256.json`, `w3c_didkey_P256.json`: copied from
  https://github.com/bluesky-social/atproto-interop-tests (`crypto/` folder, branch main). The w3c_didkey files
  are the W3C did:key test vectors as packaged by that repo.
