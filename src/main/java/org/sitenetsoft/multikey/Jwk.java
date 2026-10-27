package org.sitenetsoft.multikey;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * JSON Web Keys (RFC 7517/7518/8037) for EC (P-256, secp256k1), OKP (Ed25519) and RSA keys. JWKs are plain
 * {@code Map<String,Object>}s; exception messages name members but never include their values.
 */
public final class Jwk {
    private static final ObjectMapper MAPPER = new ObjectMapper(
            JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build())
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
    private static final BigInteger P256_N = new BigInteger(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    private static final BigInteger K256_N = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    private Jwk() {
    }

    public static Map<String, Object> parse(String json) {
        try {
            Object v = MAPPER.readValue(json, Object.class);
            if (!(v instanceof Map<?, ?>)) {
                throw new MultikeyException("JWK must be a JSON object");
            }
            return MAPPER.convertValue(v, new TypeReference<LinkedHashMap<String, Object>>() {
            });
        } catch (JsonProcessingException e) {
            throw new MultikeyException("Malformed JWK JSON");
        }
    }

    /** Serialises with members sorted by name, no whitespace. */
    public static String toJson(Map<String, Object> jwk) {
        try {
            return MAPPER.writeValueAsString(jwk);
        } catch (JsonProcessingException e) {
            throw new MultikeyException("Cannot serialise JWK", e);
        }
    }

    // ---- JWK -> key ---------------------------------------------------------------------------------------

    public static PublicKey publicKey(Map<String, Object> jwk) {
        String kty = str(jwk, "kty");
        switch (kty) {
            case "EC" -> {
                KeyType curve = ecCurve(jwk);
                byte[] x = b64(jwk, "x", 32);
                byte[] y = b64(jwk, "y", 32);
                return new Multikey(curve, EcPoints.compress(curve, new BigInteger(1, x), new BigInteger(1, y)))
                        .toPublicKey();
            }
            case "OKP" -> {
                okpCurve(jwk);
                return new Multikey(KeyType.ED25519, b64(jwk, "x", 32)).toPublicKey();
            }
            case "RSA" -> {
                return build("RSA", () -> KeyFactory.getInstance("RSA").generatePublic(
                        new RSAPublicKeySpec(uint(jwk, "n"), uint(jwk, "e"))));
            }
            default -> throw new MultikeyException("Unsupported JWK kty " + kty);
        }
    }

    public static PrivateKey privateKey(Map<String, Object> jwk) {
        String kty = str(jwk, "kty");
        switch (kty) {
            case "EC" -> {
                KeyType curve = ecCurve(jwk);
                BigInteger d = new BigInteger(1, b64(jwk, "d", 32));
                BigInteger n = curve == KeyType.P256 ? P256_N : K256_N;
                if (d.signum() == 0 || d.compareTo(n) >= 0) {
                    throw new MultikeyException("JWK member 'd' out of range");
                }
                if (curve == KeyType.SECP256K1) {
                    return Bc.secp256k1(ops -> ops.privateKey(d));
                }
                return build("EC", () -> {
                    AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
                    ap.init(new ECGenParameterSpec("secp256r1"));
                    ECParameterSpec params = ap.getParameterSpec(ECParameterSpec.class);
                    return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(d, params));
                });
            }
            case "OKP" -> {
                okpCurve(jwk);
                byte[] d = b64(jwk, "d", 32);
                return build("Ed25519", () -> KeyFactory.getInstance("Ed25519")
                        .generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, d)));
            }
            case "RSA" -> {
                BigInteger n = uint(jwk, "n");
                BigInteger d = uint(jwk, "d");
                if (jwk.containsKey("p")) {
                    RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(n, uint(jwk, "e"), d, uint(jwk, "p"),
                            uint(jwk, "q"), uint(jwk, "dp"), uint(jwk, "dq"), uint(jwk, "qi"));
                    return build("RSA", () -> KeyFactory.getInstance("RSA").generatePrivate(spec));
                }
                return build("RSA", () -> KeyFactory.getInstance("RSA")
                        .generatePrivate(new RSAPrivateKeySpec(n, d)));
            }
            default -> throw new MultikeyException("Unsupported JWK kty " + kty);
        }
    }

    // ---- key -> JWK ---------------------------------------------------------------------------------------

    public static Map<String, Object> of(PublicKey key) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        if (key instanceof ECPublicKey ec) {
            Multikey mk = Multikey.of(ec); // validates the curve
            jwk.put("kty", "EC");
            jwk.put("crv", mk.type() == KeyType.P256 ? "P-256" : "secp256k1");
            jwk.put("x", b64(fixed(ec.getW().getAffineX())));
            jwk.put("y", b64(fixed(ec.getW().getAffineY())));
        } else if (key instanceof RSAPublicKey rsa) {
            jwk.put("kty", "RSA");
            jwk.put("n", b64(unsigned(rsa.getModulus())));
            jwk.put("e", b64(unsigned(rsa.getPublicExponent())));
        } else {
            Multikey mk = Multikey.of(key);
            if (mk.type() != KeyType.ED25519) {
                throw new MultikeyException("Unsupported key for JWK: " + mk.type());
            }
            jwk.put("kty", "OKP");
            jwk.put("crv", "Ed25519");
            jwk.put("x", b64(mk.publicKeyBytes()));
        }
        return jwk;
    }

    /** The public JWK of {@code publicKey} plus the private members of {@code privateKey}. */
    public static Map<String, Object> ofPrivate(PrivateKey privateKey, PublicKey publicKey) {
        Map<String, Object> jwk = of(publicKey);
        String kty = (String) jwk.get("kty");
        if (privateKey instanceof ECPrivateKey ec && kty.equals("EC")) {
            jwk.put("d", b64(fixed(ec.getS())));
        } else if (privateKey instanceof RSAPrivateCrtKey rsa && kty.equals("RSA")) {
            jwk.put("d", b64(unsigned(rsa.getPrivateExponent())));
            jwk.put("p", b64(unsigned(rsa.getPrimeP())));
            jwk.put("q", b64(unsigned(rsa.getPrimeQ())));
            jwk.put("dp", b64(unsigned(rsa.getPrimeExponentP())));
            jwk.put("dq", b64(unsigned(rsa.getPrimeExponentQ())));
            jwk.put("qi", b64(unsigned(rsa.getCrtCoefficient())));
        } else if (privateKey instanceof RSAPrivateKey rsa && kty.equals("RSA")) {
            jwk.put("d", b64(unsigned(rsa.getPrivateExponent())));
        } else if (privateKey instanceof EdECPrivateKey ed && kty.equals("OKP")) {
            jwk.put("d", b64(ed.getBytes().orElseThrow(
                    () -> new MultikeyException("Ed25519 private key bytes are not extractable"))));
        } else {
            throw new MultikeyException("Private key " + privateKey.getAlgorithm()
                    + " does not match public key type " + kty);
        }
        return jwk;
    }

    // ---- helpers ------------------------------------------------------------------------------------------

    private interface Builder<T> {
        T build() throws Exception;
    }

    private static <T> T build(String what, Builder<T> b) {
        try {
            return b.build();
        } catch (MultikeyException e) {
            throw e;
        } catch (Exception e) {
            // no cause: JCA messages may echo key material
            throw new MultikeyException("Invalid " + what + " JWK");
        }
    }

    private static KeyType ecCurve(Map<String, Object> jwk) {
        String crv = str(jwk, "crv");
        return switch (crv) {
            case "P-256" -> KeyType.P256;
            case "secp256k1" -> KeyType.SECP256K1;
            default -> throw new MultikeyException("Unsupported EC JWK curve " + crv);
        };
    }

    private static void okpCurve(Map<String, Object> jwk) {
        String crv = str(jwk, "crv");
        if (!crv.equals("Ed25519")) {
            throw new MultikeyException("Unsupported OKP JWK curve " + crv);
        }
    }

    static String str(Map<String, Object> jwk, String name) {
        if (jwk == null || !(jwk.get(name) instanceof String s)) {
            throw new MultikeyException("JWK member '" + name + "' missing or not a string");
        }
        return s;
    }

    private static byte[] b64(Map<String, Object> jwk, String name, int expectedLength) {
        byte[] b = b64(jwk, name);
        if (b.length != expectedLength) {
            throw new MultikeyException("JWK member '" + name + "' must be " + expectedLength + " bytes");
        }
        return b;
    }

    private static byte[] b64(Map<String, Object> jwk, String name) {
        String s = str(jwk, name);
        if (s.indexOf('=') >= 0) {
            throw new MultikeyException("JWK member '" + name + "' must be unpadded base64url");
        }
        try {
            return Base64.getUrlDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            throw new MultikeyException("JWK member '" + name + "' is not valid base64url");
        }
    }

    private static BigInteger uint(Map<String, Object> jwk, String name) {
        byte[] b = b64(jwk, name);
        if (b.length == 0) {
            throw new MultikeyException("JWK member '" + name + "' is empty");
        }
        return new BigInteger(1, b);
    }

    private static String b64(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static byte[] fixed(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int len = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - len, out, 32 - len, len);
        return out;
    }

    private static byte[] unsigned(BigInteger v) {
        byte[] raw = v.toByteArray();
        if (raw.length > 1 && raw[0] == 0) {
            byte[] out = new byte[raw.length - 1];
            System.arraycopy(raw, 1, out, 0, out.length);
            return out;
        }
        return raw;
    }
}
