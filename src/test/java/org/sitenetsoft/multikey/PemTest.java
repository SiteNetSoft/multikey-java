package org.sitenetsoft.multikey;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PemTest {
    private static final byte[] DATA = "pem".getBytes(StandardCharsets.UTF_8);

    private static String resource(String name) {
        try (InputStream in = PemTest.class.getResourceAsStream("/vectors/" + name)) {
            return new String(in.readAllBytes(), StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void checkPair(String name, KeyType type, Algorithm alg) {
        List<Key> keys = Pem.parseAll(resource("pem-" + name + "-private.pem") + "\n"
                + resource("pem-" + name + "-public.pem"));
        assertEquals(2, keys.size());
        PrivateKey priv = assertInstanceOf(PrivateKey.class, keys.get(0));
        PublicKey pub = assertInstanceOf(PublicKey.class, keys.get(1));
        assertEquals(type, Multikey.of(pub).type());
        assertTrue(Signatures.verify(alg, pub, DATA, Signatures.sign(alg, priv, DATA)));
    }

    @Test
    void parsesPkcs8AndSpki() {
        checkPair("p256", KeyType.P256, Algorithm.ES256);
        checkPair("k256", KeyType.SECP256K1, Algorithm.ES256K);
        checkPair("ed25519", KeyType.ED25519, Algorithm.EDDSA);
    }

    @Test
    void encodeThenParse() {
        for (KeyType type : KeyType.values()) {
            KeyPair kp = KeyPairs.generate(type);
            String pub = Pem.encode(kp.getPublic());
            String priv = Pem.encode(kp.getPrivate());
            assertTrue(pub.startsWith("-----BEGIN PUBLIC KEY-----\n"), pub);
            assertTrue(pub.endsWith("-----END PUBLIC KEY-----\n"), pub);
            assertTrue(priv.startsWith("-----BEGIN PRIVATE KEY-----\n"));
            for (String line : (pub + priv).split("\n")) {
                assertTrue(line.length() <= 64, line);
            }
            List<Key> keys = Pem.parseAll(priv + pub);
            assertEquals(2, keys.size());
            assertEquals(Multikey.of(kp.getPublic()), Multikey.of((PublicKey) keys.get(1)));
            assertEquals(Jwk.ofPrivate(kp.getPrivate(), kp.getPublic()),
                    Jwk.ofPrivate((PrivateKey) keys.get(0), (PublicKey) keys.get(1)));
        }
    }

    @Test
    void reEncodesOpensslPemIdentically() {
        String pub = resource("pem-p256-public.pem");
        assertEquals(pub, Pem.encode(Pem.parseAll(pub).get(0)));
    }

    @Test
    void rejectsUnsupportedAndMalformed() {
        assertThrows(MultikeyException.class,
                () -> Pem.parseAll("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"));
        assertThrows(MultikeyException.class,
                () -> Pem.parseAll("-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n"));
        assertThrows(MultikeyException.class,
                () -> Pem.parseAll("-----BEGIN PUBLIC KEY-----\nMAA=\n-----END PUBLIC KEY-----\n"));
        assertEquals(List.of(), Pem.parseAll("no pem here"));
    }
}
