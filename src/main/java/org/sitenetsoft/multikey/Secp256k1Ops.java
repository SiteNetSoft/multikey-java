package org.sitenetsoft.multikey;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * The secp256k1 operations that need BouncyCastle. The only implementation, {@link Secp256k1}, is loaded by name in
 * {@link Bc}, so no other class links against BouncyCastle; that keeps native images buildable without it.
 */
interface Secp256k1Ops {
    PublicKey publicKey(BigInteger x, BigInteger y) throws Exception;

    PrivateKey privateKey(BigInteger d) throws Exception;

    PublicKey publicKeyFromSpki(byte[] der) throws Exception;

    PrivateKey privateKeyFromPkcs8(byte[] der) throws Exception;

    KeyPair generate() throws Exception;

    /** Deterministic (RFC 6979) ECDSA over a SHA-256 digest; returns {r, s} (s not yet normalised). */
    BigInteger[] sign(BigInteger d, byte[] digest);

    boolean verify(BigInteger x, BigInteger y, byte[] digest, BigInteger r, BigInteger s);
}
