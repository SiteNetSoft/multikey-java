package org.sitenetsoft.multikey;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.AlgorithmParameters;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * A public key plus its type. {@code publicKeyBytes} is the compressed point for EC keys, 32 raw bytes
 * for Ed25519 and DER SubjectPublicKeyInfo for RSA.
 */
public record Multikey(KeyType type, byte[] publicKeyBytes) {
    private static final byte[] ED25519_SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");

    public Multikey {
        publicKeyBytes = publicKeyBytes.clone();
    }

    @Override
    public byte[] publicKeyBytes() {
        return publicKeyBytes.clone();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Multikey m && m.type == type && Arrays.equals(m.publicKeyBytes, publicKeyBytes);
    }

    @Override
    public int hashCode() {
        return 31 * type.hashCode() + Arrays.hashCode(publicKeyBytes);
    }

    @Override
    public String toString() {
        return "Multikey[" + type + "]";
    }

    public static Multikey parse(String publicKeyMultibase) {
        if (publicKeyMultibase == null || !publicKeyMultibase.startsWith("z")) {
            throw new MultikeyException("Multikey must be base58btc multibase ('z' prefix)");
        }
        byte[] raw = Multibase.decode(publicKeyMultibase);
        int[] code = Varint.decode(raw);
        KeyType type = KeyType.fromMulticodec(code[0]);
        byte[] key = Arrays.copyOfRange(raw, code[1], raw.length);
        switch (type) {
            case P256, SECP256K1 -> {
                EcPoints.decompress(type, key); // validates length and curve membership
            }
            case ED25519 -> {
                if (key.length != 32) {
                    throw new MultikeyException("Ed25519 key must be 32 bytes");
                }
            }
            case RSA -> {
                if (key.length == 0) {
                    throw new MultikeyException("Empty RSA key");
                }
            }
        }
        return new Multikey(type, key);
    }

    public String encode() {
        byte[] prefix = Varint.encode(type.multicodec());
        byte[] all = new byte[prefix.length + publicKeyBytes.length];
        System.arraycopy(prefix, 0, all, 0, prefix.length);
        System.arraycopy(publicKeyBytes, 0, all, prefix.length, publicKeyBytes.length);
        return Multibase.encodeBase58btc(all);
    }

    public static Multikey of(PublicKey key) {
        String alg = key.getAlgorithm();
        if (key instanceof ECPublicKey ec) {
            KeyType type = ec.getParams().getCurve().getA().signum() == 0 ? KeyType.SECP256K1 : KeyType.P256;
            return new Multikey(type, EcPoints.compress(type, ec.getW().getAffineX(), ec.getW().getAffineY()));
        }
        if ("Ed25519".equalsIgnoreCase(alg) || "EdDSA".equalsIgnoreCase(alg)) {
            byte[] enc = key.getEncoded();
            if (enc == null || enc.length < 32) {
                throw new MultikeyException("Cannot encode Ed25519 key");
            }
            return new Multikey(KeyType.ED25519, Arrays.copyOfRange(enc, enc.length - 32, enc.length));
        }
        if ("RSA".equalsIgnoreCase(alg)) {
            return new Multikey(KeyType.RSA, key.getEncoded());
        }
        throw new MultikeyException("Unsupported key algorithm " + alg);
    }

    public PublicKey toPublicKey() {
        try {
            switch (type) {
                case P256 -> {
                    BigInteger[] xy = EcPoints.decompress(type, publicKeyBytes);
                    AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
                    ap.init(new ECGenParameterSpec("secp256r1"));
                    ECParameterSpec spec = ap.getParameterSpec(ECParameterSpec.class);
                    return KeyFactory.getInstance("EC")
                            .generatePublic(new ECPublicKeySpec(new ECPoint(xy[0], xy[1]), spec));
                }
                case SECP256K1 -> {
                    BigInteger[] xy = EcPoints.decompress(type, publicKeyBytes);
                    try {
                        return Secp256k1.publicKey(xy[0], xy[1]);
                    } catch (NoClassDefFoundError e) {
                        throw new MultikeyException(
                                "secp256k1 needs org.bouncycastle:bcprov-jdk18on on the classpath", e);
                    }
                }
                case ED25519 -> {
                    byte[] spki = new byte[ED25519_SPKI_PREFIX.length + 32];
                    System.arraycopy(ED25519_SPKI_PREFIX, 0, spki, 0, ED25519_SPKI_PREFIX.length);
                    System.arraycopy(publicKeyBytes, 0, spki, ED25519_SPKI_PREFIX.length, 32);
                    return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
                }
                case RSA -> {
                    return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
                }
                default -> throw new MultikeyException("Unsupported key type " + type);
            }
        } catch (MultikeyException e) {
            throw e;
        } catch (Exception e) {
            throw new MultikeyException("Cannot build " + type + " public key", e);
        }
    }
}
