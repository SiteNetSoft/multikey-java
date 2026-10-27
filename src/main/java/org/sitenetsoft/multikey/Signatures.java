package org.sitenetsoft.multikey;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.ECFieldFp;
import java.util.Arrays;

/**
 * JWS-style signatures. ES256 and ES256K produce and accept only 64-byte compact {@code r‖s}; signing always
 * yields low-S and {@link #verify} rejects high-S (the AT Protocol rule), while {@link #verifyAllowHighS} accepts
 * either (for JWTs from other ecosystems). ES256 uses the JDK; ES256K uses BouncyCastle with RFC 6979
 * deterministic nonces.
 */
public final class Signatures {
    private static final BigInteger P256_N = new BigInteger(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    private static final BigInteger K256_N = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    private Signatures() {
    }

    public static byte[] sign(Algorithm alg, PrivateKey key, byte[] data) {
        checkKey(alg, key);
        try {
            switch (alg) {
                case ES256 -> {
                    return normaliseLowS(KeyType.P256, jdkSign("SHA256withECDSAinP1363Format", key, data));
                }
                case ES256K -> {
                    BigInteger d = ((ECPrivateKey) key).getS();
                    byte[] digest = sha256(data);
                    BigInteger[] rs = Bc.secp256k1(() -> Secp256k1.sign(d, digest));
                    return normaliseLowS(KeyType.SECP256K1, compact(rs[0], rs[1]));
                }
                case EDDSA -> {
                    return jdkSign("Ed25519", key, data);
                }
                case RS256 -> {
                    return jdkSign("SHA256withRSA", key, data);
                }
                default -> throw new MultikeyException("Unsupported algorithm " + alg);
            }
        } catch (GeneralSecurityException e) {
            // no cause: provider messages may echo key material
            throw new MultikeyException(alg.jwsName() + " signing failed");
        }
    }

    /** Verifies; for ES256/ES256K the signature must be 64-byte compact and low-S. */
    public static boolean verify(Algorithm alg, PublicKey key, byte[] data, byte[] sig) {
        return verify(alg, key, data, sig, false);
    }

    /** Like {@link #verify} but accepts high-S ES256/ES256K signatures (still 64-byte compact only). */
    public static boolean verifyAllowHighS(Algorithm alg, PublicKey key, byte[] data, byte[] sig) {
        return verify(alg, key, data, sig, true);
    }

    private static boolean verify(Algorithm alg, PublicKey key, byte[] data, byte[] sig, boolean allowHighS) {
        checkKey(alg, key);
        if (sig == null) {
            return false;
        }
        try {
            switch (alg) {
                case ES256, ES256K -> {
                    KeyType curve = alg == Algorithm.ES256 ? KeyType.P256 : KeyType.SECP256K1;
                    if (sig.length != 64) {
                        return false;
                    }
                    BigInteger n = order(curve);
                    BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig, 0, 32));
                    BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, 32, 64));
                    if (r.signum() == 0 || s.signum() == 0 || r.compareTo(n) >= 0 || s.compareTo(n) >= 0) {
                        return false;
                    }
                    if (!allowHighS && s.compareTo(n.shiftRight(1)) > 0) {
                        return false;
                    }
                    if (alg == Algorithm.ES256) {
                        return jdkVerify("SHA256withECDSAinP1363Format", key, data, sig);
                    }
                    ECPublicKey ec = (ECPublicKey) key;
                    BigInteger x = ec.getW().getAffineX();
                    BigInteger y = ec.getW().getAffineY();
                    byte[] digest = sha256(data);
                    return Bc.secp256k1(() -> Secp256k1.verify(x, y, digest, r, s));
                }
                case EDDSA -> {
                    return jdkVerify("Ed25519", key, data, sig);
                }
                case RS256 -> {
                    return jdkVerify("SHA256withRSA", key, data, sig);
                }
                default -> throw new MultikeyException("Unsupported algorithm " + alg);
            }
        } catch (SignatureException e) {
            return false;
        } catch (GeneralSecurityException e) {
            throw new MultikeyException(alg.jwsName() + " verification failed", e);
        }
    }

    /** Returns a copy of the 64-byte compact signature with s replaced by n − s when s &gt; n/2. */
    public static byte[] normaliseLowS(KeyType curve, byte[] compactSig) {
        BigInteger n = order(curve);
        checkCompact(compactSig);
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(compactSig, 32, 64));
        byte[] out = compactSig.clone();
        if (s.compareTo(n.shiftRight(1)) > 0) {
            System.arraycopy(fixed(n.subtract(s)), 0, out, 32, 32);
        }
        return out;
    }

    /** True when s ≤ n/2. */
    public static boolean isLowS(KeyType curve, byte[] compactSig) {
        BigInteger n = order(curve);
        checkCompact(compactSig);
        return new BigInteger(1, Arrays.copyOfRange(compactSig, 32, 64)).compareTo(n.shiftRight(1)) <= 0;
    }

    // ---- helpers ------------------------------------------------------------------------------------------

    private static BigInteger order(KeyType curve) {
        return switch (curve) {
            case P256 -> P256_N;
            case SECP256K1 -> K256_N;
            default -> throw new MultikeyException("Not an ECDSA curve: " + curve);
        };
    }

    private static void checkCompact(byte[] sig) {
        if (sig == null || sig.length != 64) {
            throw new MultikeyException("ECDSA signature must be 64-byte compact r||s");
        }
    }

    /** Throws when the key cannot be used with the algorithm (wrong family or curve). */
    private static void checkKey(Algorithm alg, Key key) {
        boolean ok = switch (alg) {
            case ES256 -> curveOf(key) == KeyType.P256;
            case ES256K -> curveOf(key) == KeyType.SECP256K1;
            case EDDSA -> "Ed25519".equalsIgnoreCase(key.getAlgorithm())
                    || "EdDSA".equalsIgnoreCase(key.getAlgorithm());
            case RS256 -> key instanceof RSAKey;
        };
        if (!ok) {
            throw new MultikeyException(alg.jwsName() + " cannot use a " + key.getAlgorithm() + " key"
                    + (key instanceof ECKey ? " on this curve" : ""));
        }
    }

    private static KeyType curveOf(Key key) {
        if (key instanceof ECKey ec && ec.getParams() != null
                && ec.getParams().getCurve().getField() instanceof ECFieldFp fp) {
            return EcPoints.curveOfPrime(fp.getP());
        }
        return null;
    }

    private static byte[] jdkSign(String algorithm, PrivateKey key, byte[] data) throws GeneralSecurityException {
        Signature s = Signature.getInstance(algorithm);
        s.initSign(key);
        s.update(data);
        return s.sign();
    }

    private static boolean jdkVerify(String algorithm, PublicKey key, byte[] data, byte[] sig)
            throws GeneralSecurityException {
        Signature s = Signature.getInstance(algorithm);
        s.initVerify(key);
        s.update(data);
        return s.verify(sig);
    }

    private static byte[] sha256(byte[] data) throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private static byte[] compact(BigInteger r, BigInteger s) {
        byte[] out = new byte[64];
        System.arraycopy(fixed(r), 0, out, 0, 32);
        System.arraycopy(fixed(s), 0, out, 32, 32);
        return out;
    }

    private static byte[] fixed(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int len = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - len, out, 32 - len, len);
        return out;
    }
}
