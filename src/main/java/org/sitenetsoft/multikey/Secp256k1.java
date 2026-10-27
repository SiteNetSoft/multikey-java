package org.sitenetsoft.multikey;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;

/** BouncyCastle-backed secp256k1 support; loaded only when BouncyCastle is on the classpath. */
final class Secp256k1 {
    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    private Secp256k1() {
    }

    static PublicKey publicKey(BigInteger x, BigInteger y) throws Exception {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
        return KeyFactory.getInstance("EC", BC)
                .generatePublic(new ECPublicKeySpec(spec.getCurve().createPoint(x, y), spec));
    }
}
