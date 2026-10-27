package org.sitenetsoft.multikey;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwkTest {
    private static final byte[] DATA = "jwk round trip".getBytes(StandardCharsets.UTF_8);

    private static void roundTrip(KeyType type, Algorithm alg, String kty, String crv) {
        KeyPair kp = KeyPairs.generate(type);
        Map<String, Object> pub = Jwk.of(kp.getPublic());
        assertEquals(kty, pub.get("kty"));
        assertEquals(crv, pub.get("crv"));
        assertFalse(pub.containsKey("d"));
        Map<String, Object> priv = Jwk.ofPrivate(kp.getPrivate(), kp.getPublic());
        assertTrue(priv.containsKey("d"));

        // through JSON and back
        Map<String, Object> pub2 = Jwk.parse(Jwk.toJson(pub));
        Map<String, Object> priv2 = Jwk.parse(Jwk.toJson(priv));
        assertEquals(pub, pub2);
        assertEquals(priv, priv2);

        var publicKey = Jwk.publicKey(pub2);
        var privateKey = Jwk.privateKey(priv2);
        assertEquals(Multikey.of(kp.getPublic()), Multikey.of(publicKey));
        assertEquals(pub, Jwk.of(publicKey));
        assertEquals(priv, Jwk.ofPrivate(privateKey, publicKey));
        // a private key built from the JWK signs for the original public key
        assertTrue(Signatures.verify(alg, kp.getPublic(), DATA, Signatures.sign(alg, privateKey, DATA)));
        // a public key built from the JWK accepts signatures from the original private key
        assertTrue(Signatures.verify(alg, publicKey, DATA, Signatures.sign(alg, kp.getPrivate(), DATA)));
    }

    @Test
    void ecRoundTrip() {
        roundTrip(KeyType.P256, Algorithm.ES256, "EC", "P-256");
    }

    @Test
    void okpRoundTrip() {
        roundTrip(KeyType.ED25519, Algorithm.EDDSA, "OKP", "Ed25519");
    }

    @Test
    void secp256k1RoundTrip() {
        roundTrip(KeyType.SECP256K1, Algorithm.ES256K, "EC", "secp256k1");
    }

    @Test
    void rsaRoundTrip() {
        roundTrip(KeyType.RSA, Algorithm.RS256, "RSA", null);
    }

    @Test
    void toJsonSortsMembers() {
        assertEquals("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"a\",\"y\":\"b\"}",
                Jwk.toJson(Map.of("y", "b", "kty", "EC", "x", "a", "crv", "P-256")));
    }

    @Test
    void ecCoordinatesArePadded() {
        // EC coordinates are always 32 bytes (43 base64url chars), even with leading zero bytes
        for (int i = 0; i < 40; i++) {
            Map<String, Object> pub = Jwk.of(KeyPairs.generate(KeyType.P256).getPublic());
            assertEquals(43, ((String) pub.get("x")).length());
            assertEquals(43, ((String) pub.get("y")).length());
        }
    }

    @Test
    void rejectsPointOffCurve() {
        Map<String, Object> pub = new java.util.HashMap<>(Jwk.of(KeyPairs.generate(KeyType.P256).getPublic()));
        pub.put("y", pub.get("x"));
        assertThrows(MultikeyException.class, () -> Jwk.publicKey(pub));
    }

    @Test
    void rejectsUnsupportedCurveAndKty() {
        assertThrows(MultikeyException.class,
                () -> Jwk.publicKey(Map.of("kty", "EC", "crv", "P-384", "x", "AA", "y", "AA")));
        assertThrows(MultikeyException.class, () -> Jwk.publicKey(Map.of("kty", "oct", "k", "AA")));
        assertThrows(MultikeyException.class, () -> Jwk.parse("[1,2]"));
    }

    @Test
    void errorsDoNotLeakPrivateMaterial() {
        Map<String, Object> priv = new java.util.HashMap<>(
                Jwk.ofPrivate(KeyPairs.generate(KeyType.P256).getPrivate(),
                        KeyPairs.generate(KeyType.P256).getPublic()));
        String d = (String) priv.get("d");
        priv.put("d", d + "!!");
        MultikeyException e = assertThrows(MultikeyException.class, () -> Jwk.privateKey(priv));
        assertFalse(e.getMessage().contains(d));
    }

    @Test
    void ed25519PublicBytesMatchMultikey() {
        KeyPair kp = KeyPairs.generate(KeyType.ED25519);
        byte[] x = java.util.Base64.getUrlDecoder().decode((String) Jwk.of(kp.getPublic()).get("x"));
        assertArrayEquals(Multikey.of(kp.getPublic()).publicKeyBytes(), x);
    }
}
