package org.sitenetsoft.multikey;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.*;

class DidKeyTest {
    @Test
    void roundTrip() throws Exception {
        assertEquals(Vectors.p256Did(), DidKey.of(DidKey.parse(Vectors.p256Did())));
        assertEquals(Vectors.k256Did(), DidKey.of(DidKey.parse(Vectors.k256Did())));
        for (var node : Vectors.load("w3c_didkey_K256.json")) {
            String did = node.get("publicDidKey").asText();
            assertEquals(did, DidKey.of(DidKey.parse(did)));
        }
        for (var node : Vectors.load("w3c_didkey_P256.json")) {
            String did = node.get("publicDidKey").asText();
            assertEquals(did, DidKey.of(DidKey.parse(did)));
        }
        assertThrows(MultikeyException.class, () -> DidKey.parse("did:web:example.com"));
    }

    @Test
    void ed25519AndRsaRoundTripThroughJdk() throws Exception {
        KeyPair ed = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        Multikey m = Multikey.of(ed.getPublic());
        assertEquals(KeyType.ED25519, m.type());
        assertEquals(32, m.publicKeyBytes().length);
        assertEquals(ed.getPublic(), Multikey.parse(m.encode()).toPublicKey());

        KeyPairGenerator rg = KeyPairGenerator.getInstance("RSA");
        rg.initialize(2048);
        KeyPair rsa = rg.generateKeyPair();
        Multikey r = Multikey.of(rsa.getPublic());
        assertEquals(KeyType.RSA, r.type());
        assertEquals(rsa.getPublic(), Multikey.parse(r.encode()).toPublicKey());
    }

    @Test
    void toPublicKeyVerifiesJdkSignature() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();
        String did = DidKey.of(Multikey.of(kp.getPublic()));
        assertTrue(did.startsWith("did:key:zDnae"));

        byte[] msg = "hello".getBytes();
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(kp.getPrivate());
        s.update(msg);
        byte[] sig = s.sign();

        PublicKey pub = DidKey.parse(did).toPublicKey();
        Signature v = Signature.getInstance("SHA256withECDSA");
        v.initVerify(pub);
        v.update(msg);
        assertTrue(v.verify(sig));
    }

    @Test
    void secp256k1ToPublicKeyWorksWithBouncyCastle() throws Exception {
        PublicKey pub = DidKey.parse(Vectors.k256Did()).toPublicKey();
        assertEquals("EC", pub.getAlgorithm());
        assertEquals(Vectors.k256Did(), DidKey.of(Multikey.of(pub)));
    }
}
