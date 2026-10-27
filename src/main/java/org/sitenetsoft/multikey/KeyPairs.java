package org.sitenetsoft.multikey;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

/** Fresh key pairs: P-256, Ed25519 and RSA-2048 through the JDK, secp256k1 through BouncyCastle. */
public final class KeyPairs {
    private KeyPairs() {
    }

    public static KeyPair generate(KeyType type) {
        try {
            switch (type) {
                case P256 -> {
                    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
                    g.initialize(new ECGenParameterSpec("secp256r1"));
                    return g.generateKeyPair();
                }
                case ED25519 -> {
                    return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
                }
                case RSA -> {
                    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
                    g.initialize(2048);
                    return g.generateKeyPair();
                }
                case SECP256K1 -> {
                    return Bc.secp256k1(() -> Secp256k1.generate());
                }
                default -> throw new MultikeyException("Unsupported key type " + type);
            }
        } catch (GeneralSecurityException e) {
            throw new MultikeyException("Cannot generate " + type + " key pair", e);
        }
    }
}
