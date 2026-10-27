# multikey-java

Plain Java 21 library: base58btc/base64url multibase, varint multicodec, Multikey, `did:key` and EC point
compression (P-256, secp256k1). BouncyCastle (`bcprov-jdk18on`) is optional and only needed for secp256k1 keys.

In a GraalVM native image, secp256k1 operations that need BouncyCastle (key objects, ES256K signing and
verification) are not available yet and fail with the same "needs bcprov-jdk18on" error; multibase, Multikey,
`did:key` and point compression work for every key type.

```java
Multikey key = DidKey.parse("did:key:zDnaembgSGUhZULN2Caob4HLJPaxBh92N7rtH21TErzqf8HQo");
PublicKey pub = key.toPublicKey();
```

Apache License 2.0.
