package org.sitenetsoft.multikey;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignaturesTest {
    private static final BigInteger K256_N = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private static final BigInteger P256_N = new BigInteger(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    private static final byte[] DATA = "hello atproto".getBytes(StandardCharsets.UTF_8);

    private static byte[] flipS(byte[] sig, BigInteger n) {
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, 32, 64));
        byte[] out = sig.clone();
        byte[] flipped = n.subtract(s).toByteArray();
        Arrays.fill(out, 32, 64, (byte) 0);
        int len = Math.min(flipped.length, 32);
        System.arraycopy(flipped, flipped.length - len, out, 64 - len, len);
        return out;
    }

    @Test
    void algorithmNames() {
        assertEquals("ES256", Algorithm.ES256.jwsName());
        assertEquals("ES256K", Algorithm.ES256K.jwsName());
        assertEquals("EdDSA", Algorithm.EDDSA.jwsName());
        assertEquals("RS256", Algorithm.RS256.jwsName());
    }

    @Test
    void es256SignVerify() {
        KeyPair kp = KeyPairs.generate(KeyType.P256);
        byte[] sig = Signatures.sign(Algorithm.ES256, kp.getPrivate(), DATA);
        assertEquals(64, sig.length);
        assertTrue(Signatures.verify(Algorithm.ES256, kp.getPublic(), DATA, sig));
        assertFalse(Signatures.verify(Algorithm.ES256, kp.getPublic(), "other".getBytes(), sig));
        assertFalse(Signatures.verify(Algorithm.ES256, KeyPairs.generate(KeyType.P256).getPublic(), DATA, sig));
        assertFalse(Signatures.verify(Algorithm.ES256, kp.getPublic(), DATA, Arrays.copyOf(sig, 63)));
    }

    @Test
    void es256OutputIsLowS() {
        KeyPair kp = KeyPairs.generate(KeyType.P256);
        for (int i = 0; i < 100; i++) {
            byte[] sig = Signatures.sign(Algorithm.ES256, kp.getPrivate(), (i + "").getBytes());
            assertEquals(64, sig.length);
            assertTrue(Signatures.isLowS(KeyType.P256, sig));
        }
    }

    @Test
    void es256RejectsHighS() {
        KeyPair kp = KeyPairs.generate(KeyType.P256);
        byte[] high = flipS(Signatures.sign(Algorithm.ES256, kp.getPrivate(), DATA), P256_N);
        assertFalse(Signatures.isLowS(KeyType.P256, high));
        assertFalse(Signatures.verify(Algorithm.ES256, kp.getPublic(), DATA, high));
        assertTrue(Signatures.verifyAllowHighS(Algorithm.ES256, kp.getPublic(), DATA, high));
        byte[] low = Signatures.normaliseLowS(KeyType.P256, high);
        assertTrue(Signatures.isLowS(KeyType.P256, low));
        assertTrue(Signatures.verify(Algorithm.ES256, kp.getPublic(), DATA, low));
    }

    @Test
    void es256KRejectsHighS() {
        KeyPair kp = KeyPairs.generate(KeyType.SECP256K1);
        byte[] sig = Signatures.sign(Algorithm.ES256K, kp.getPrivate(), DATA);
        assertEquals(64, sig.length);
        assertTrue(Signatures.isLowS(KeyType.SECP256K1, sig));
        assertTrue(Signatures.verify(Algorithm.ES256K, kp.getPublic(), DATA, sig));
        byte[] high = flipS(sig, K256_N);
        assertFalse(Signatures.verify(Algorithm.ES256K, kp.getPublic(), DATA, high));
        assertTrue(Signatures.verifyAllowHighS(Algorithm.ES256K, kp.getPublic(), DATA, high));
        assertArrayEquals(sig, Signatures.normaliseLowS(KeyType.SECP256K1, high));
    }

    @Test
    void es256KDeterministic() {
        KeyPair kp = KeyPairs.generate(KeyType.SECP256K1);
        byte[] a = Signatures.sign(Algorithm.ES256K, kp.getPrivate(), DATA);
        byte[] b = Signatures.sign(Algorithm.ES256K, kp.getPrivate(), DATA);
        assertArrayEquals(a, b);
        for (int i = 0; i < 50; i++) {
            assertTrue(Signatures.isLowS(KeyType.SECP256K1,
                    Signatures.sign(Algorithm.ES256K, kp.getPrivate(), (i + "").getBytes())));
        }
    }

    @Test
    void eddsaAndRs256SignVerify() {
        for (var c : new Object[][] {{KeyType.ED25519, Algorithm.EDDSA}, {KeyType.RSA, Algorithm.RS256}}) {
            KeyPair kp = KeyPairs.generate((KeyType) c[0]);
            Algorithm alg = (Algorithm) c[1];
            byte[] sig = Signatures.sign(alg, kp.getPrivate(), DATA);
            assertTrue(Signatures.verify(alg, kp.getPublic(), DATA, sig));
            assertFalse(Signatures.verify(alg, kp.getPublic(), "x".getBytes(), sig));
        }
    }

    @Test
    void rejectsKeyAlgorithmMismatch() {
        KeyPair k1 = KeyPairs.generate(KeyType.SECP256K1);
        KeyPair p256 = KeyPairs.generate(KeyType.P256);
        assertThrows(MultikeyException.class, () -> Signatures.sign(Algorithm.ES256, k1.getPrivate(), DATA));
        assertThrows(MultikeyException.class, () -> Signatures.sign(Algorithm.ES256K, p256.getPrivate(), DATA));
        assertThrows(MultikeyException.class, () -> Signatures.sign(Algorithm.EDDSA, p256.getPrivate(), DATA));
        assertThrows(MultikeyException.class,
                () -> Signatures.verify(Algorithm.ES256K, p256.getPublic(), DATA, new byte[64]));
    }

    @Test
    void lowSHelpersRejectWrongLength() {
        assertThrows(MultikeyException.class, () -> Signatures.isLowS(KeyType.P256, new byte[70]));
        assertThrows(MultikeyException.class, () -> Signatures.normaliseLowS(KeyType.ED25519, new byte[64]));
    }

    @Test
    void atprotoVectors() {
        JsonNode fixtures = Vectors.load("signature-fixtures.json");
        assertEquals(6, fixtures.size());
        int valid = 0;
        for (JsonNode f : fixtures) {
            String comment = f.get("comment").asText();
            Algorithm alg = Algorithm.valueOf(f.get("algorithm").asText());
            PublicKey key = DidKey.parse(f.get("publicKeyDid").asText()).toPublicKey();
            assertEquals(alg == Algorithm.ES256 ? KeyType.P256 : KeyType.SECP256K1, Multikey.of(key).type());
            byte[] message = Base64.getDecoder().decode(f.get("messageBase64").asText());
            byte[] sig = Base64.getDecoder().decode(f.get("signatureBase64").asText());
            boolean expected = f.get("validSignature").asBoolean();
            assertEquals(expected, Signatures.verify(alg, key, message, sig), comment);
            boolean highS = f.get("tags").toString().contains("high-s");
            if (highS) {
                assertTrue(Signatures.verifyAllowHighS(alg, key, message, sig), comment);
                assertTrue(Signatures.verify(alg, key, message,
                        Signatures.normaliseLowS(Multikey.of(key).type(), sig)), comment);
            }
            if (expected) {
                valid++;
            }
        }
        assertEquals(2, valid);
    }

    /** Hides BouncyCastle and loads the library classes afresh from target/classes. */
    private static final class NoBouncyCastle extends URLClassLoader {
        NoBouncyCastle(URL classes) {
            super(new URL[] {classes}, SignaturesTest.class.getClassLoader());
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (name.startsWith("org.bouncycastle.")) {
                throw new ClassNotFoundException(name);
            }
            if (name.startsWith("org.sitenetsoft.multikey.")) {
                synchronized (getClassLoadingLock(name)) {
                    Class<?> c = findLoadedClass(name);
                    if (c == null) {
                        c = findClass(name);
                    }
                    return c;
                }
            }
            return super.loadClass(name, resolve);
        }
    }

    @Test
    void worksWithoutBouncyCastle() throws Exception {
        URL classes = Signatures.class.getProtectionDomain().getCodeSource().getLocation();
        try (NoBouncyCastle cl = new NoBouncyCastle(classes)) {
            Class<?> keyType = cl.loadClass("org.sitenetsoft.multikey.KeyType");
            Class<?> algorithm = cl.loadClass("org.sitenetsoft.multikey.Algorithm");
            Class<?> keyPairs = cl.loadClass("org.sitenetsoft.multikey.KeyPairs");
            Class<?> signatures = cl.loadClass("org.sitenetsoft.multikey.Signatures");
            Class<?> jwk = cl.loadClass("org.sitenetsoft.multikey.Jwk");
            Class<?> pem = cl.loadClass("org.sitenetsoft.multikey.Pem");
            Method generate = keyPairs.getMethod("generate", keyType);
            Method sign = signatures.getMethod("sign", algorithm, java.security.PrivateKey.class, byte[].class);
            Method verify = signatures.getMethod("verify", algorithm, PublicKey.class, byte[].class, byte[].class);
            Object es256 = Enum.valueOf(algorithm.asSubclass(Enum.class), "ES256");
            Object eddsa = Enum.valueOf(algorithm.asSubclass(Enum.class), "EDDSA");
            Object es256k = Enum.valueOf(algorithm.asSubclass(Enum.class), "ES256K");

            for (var c : new Object[][] {{"P256", es256}, {"ED25519", eddsa}}) {
                KeyPair kp = (KeyPair) generate.invoke(null, Enum.valueOf(keyType.asSubclass(Enum.class),
                        (String) c[0]));
                byte[] sig = (byte[]) sign.invoke(null, c[1], kp.getPrivate(), DATA);
                assertEquals(true, verify.invoke(null, c[1], kp.getPublic(), DATA, sig));
                Object json = jwk.getMethod("of", PublicKey.class).invoke(null, kp.getPublic());
                assertInstanceOf(java.util.Map.class, json);
                String encoded = (String) pem.getMethod("encode", java.security.Key.class)
                        .invoke(null, kp.getPublic());
                assertEquals(1, ((java.util.List<?>) pem.getMethod("parseAll", String.class)
                        .invoke(null, encoded)).size());
            }

            Object k1 = Enum.valueOf(keyType.asSubclass(Enum.class), "SECP256K1");
            InvocationTargetException e = assertThrows(InvocationTargetException.class,
                    () -> generate.invoke(null, k1));
            assertEquals("org.sitenetsoft.multikey.MultikeyException", e.getCause().getClass().getName());
            assertEquals("secp256k1 needs org.bouncycastle:bcprov-jdk18on on the classpath",
                    e.getCause().getMessage());

            // a secp256k1 key made elsewhere: JWK export needs no BouncyCastle, ES256K verification does
            KeyPair foreignK1 = KeyPairs.generate(KeyType.SECP256K1);
            Object k1Jwk = jwk.getMethod("of", PublicKey.class).invoke(null, foreignK1.getPublic());
            assertEquals("secp256k1", ((java.util.Map<?, ?>) k1Jwk).get("crv"));
            InvocationTargetException e2 = assertThrows(InvocationTargetException.class,
                    () -> verify.invoke(null, es256k, foreignK1.getPublic(), DATA,
                            Signatures.sign(Algorithm.ES256K, foreignK1.getPrivate(), DATA)));
            assertEquals("org.sitenetsoft.multikey.MultikeyException", e2.getCause().getClass().getName());
            assertEquals("secp256k1 needs org.bouncycastle:bcprov-jdk18on on the classpath",
                    e2.getCause().getMessage());
        }
    }
}
