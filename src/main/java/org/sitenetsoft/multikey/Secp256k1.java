package org.sitenetsoft.multikey;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * BouncyCastle-backed secp256k1 support. Every BouncyCastle reference in the library lives here, and nothing names
 * this class except {@link Bc}, which loads it by name; callers go through {@link Bc#secp256k1}.
 */
final class Secp256k1 implements Secp256k1Ops {
    private static final BouncyCastleProvider BC = new BouncyCastleProvider();
    private static final X9ECParameters X9 = CustomNamedCurves.getByName("secp256k1");
    private static final ECDomainParameters DOMAIN =
            new ECDomainParameters(X9.getCurve(), X9.getG(), X9.getN(), X9.getH());

    /** Called reflectively by {@link Bc}. */
    Secp256k1() {
    }

    private static ECNamedCurveParameterSpec spec() {
        return ECNamedCurveTable.getParameterSpec("secp256k1");
    }

    @Override
    public PublicKey publicKey(BigInteger x, BigInteger y) throws Exception {
        ECNamedCurveParameterSpec spec = spec();
        return KeyFactory.getInstance("EC", BC)
                .generatePublic(new ECPublicKeySpec(spec.getCurve().createPoint(x, y), spec));
    }

    @Override
    public PrivateKey privateKey(BigInteger d) throws Exception {
        return KeyFactory.getInstance("EC", BC).generatePrivate(new ECPrivateKeySpec(d, spec()));
    }

    @Override
    public PublicKey publicKeyFromSpki(byte[] der) throws Exception {
        return KeyFactory.getInstance("EC", BC).generatePublic(new X509EncodedKeySpec(der));
    }

    @Override
    public PrivateKey privateKeyFromPkcs8(byte[] der) throws Exception {
        return KeyFactory.getInstance("EC", BC).generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    @Override
    public KeyPair generate() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC", BC);
        g.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());
        return g.generateKeyPair();
    }

    @Override
    public BigInteger[] sign(BigInteger d, byte[] digest) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(d, DOMAIN));
        return signer.generateSignature(digest);
    }

    @Override
    public boolean verify(BigInteger x, BigInteger y, byte[] digest, BigInteger r, BigInteger s) {
        ECDSASigner signer = new ECDSASigner();
        signer.init(false, new ECPublicKeyParameters(DOMAIN.getCurve().createPoint(x, y), DOMAIN));
        return signer.verifySignature(digest, r, s);
    }
}
