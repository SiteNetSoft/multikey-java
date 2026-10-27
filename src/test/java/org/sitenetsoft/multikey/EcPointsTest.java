package org.sitenetsoft.multikey;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.*;

class EcPointsTest {
    @Test
    void decompressInvertsCompressP256() throws Exception {
        for (int i = 0; i < 20; i++) {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair kp = g.generateKeyPair();
            BigInteger x = ((ECPublicKey) kp.getPublic()).getW().getAffineX();
            BigInteger y = ((ECPublicKey) kp.getPublic()).getW().getAffineY();
            byte[] c = EcPoints.compress(KeyType.P256, x, y);
            assertEquals(33, c.length);
            BigInteger[] xy = EcPoints.decompress(KeyType.P256, c);
            assertEquals(x, xy[0]);
            assertEquals(y, xy[1]);
        }
    }

    @Test
    void decompressInvertsCompressK256() {
        var json = Vectors.load("w3c_didkey_K256.json");
        var params = ECNamedCurveTable.getParameterSpec("secp256k1");
        for (var node : json) {
            BigInteger d = new BigInteger(node.get("privateKeyBytesHex").asText(), 16);
            ECPoint q = params.getG().multiply(d).normalize();
            BigInteger x = q.getAffineXCoord().toBigInteger();
            BigInteger y = q.getAffineYCoord().toBigInteger();
            byte[] c = EcPoints.compress(KeyType.SECP256K1, x, y);
            BigInteger[] xy = EcPoints.decompress(KeyType.SECP256K1, c);
            assertEquals(x, xy[0]);
            assertEquals(y, xy[1]);
            // and it matches the did:key published with the vector
            String did = node.get("publicDidKey").asText();
            assertArrayEquals(c, DidKey.parse(did).publicKeyBytes());
        }
    }

    @Test
    void rejectsPointNotOnCurve() {
        // about half of all x values have no y: scan small x until decompress rejects one
        int rejected = 0;
        for (int x = 1; x <= 20; x++) {
            byte[] c = new byte[33];
            c[0] = 2;
            c[32] = (byte) x;
            try {
                EcPoints.decompress(KeyType.P256, c);
            } catch (MultikeyException e) {
                rejected++;
            }
        }
        assertTrue(rejected > 0);
        assertThrows(MultikeyException.class,
                () -> EcPoints.compress(KeyType.P256, BigInteger.ONE, BigInteger.TWO));
        byte[] badPrefix = new byte[33];
        badPrefix[0] = 4;
        assertThrows(MultikeyException.class, () -> EcPoints.decompress(KeyType.SECP256K1, badPrefix));
    }
}
