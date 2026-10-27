# multikey-java

Plain Java 21 library: base58btc/base64url multibase, varint multicodec, Multikey, `did:key` and EC point
compression (P-256, secp256k1). BouncyCastle (`bcprov-jdk18on`) is optional and only needed for secp256k1 keys.

```java
Multikey key = DidKey.parse("did:key:zDnaembgSGUhZULN2Caob4HLJPaxBh92N7rtH21TErzqf8HQo");
PublicKey pub = key.toPublicKey();
```

Apache License 2.0.
