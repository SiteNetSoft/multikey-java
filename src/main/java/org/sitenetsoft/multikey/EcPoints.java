package org.sitenetsoft.multikey;

import java.math.BigInteger;

/** Compressed-point encoding for P-256 and secp256k1 using plain BigInteger maths. */
public final class EcPoints {
    private static final BigInteger P256_P = new BigInteger(
            "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
    private static final BigInteger P256_A = P256_P.subtract(BigInteger.valueOf(3));
    private static final BigInteger P256_B = new BigInteger(
            "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16);
    private static final BigInteger K256_P = new BigInteger(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    private static final BigInteger K256_B = BigInteger.valueOf(7);

    private EcPoints() {
    }

    private static BigInteger p(KeyType c) {
        return switch (c) {
            case P256 -> P256_P;
            case SECP256K1 -> K256_P;
            default -> throw new MultikeyException("Not an EC curve: " + c);
        };
    }

    private static BigInteger a(KeyType c) {
        return c == KeyType.P256 ? P256_A : BigInteger.ZERO;
    }

    private static BigInteger b(KeyType c) {
        return c == KeyType.P256 ? P256_B : K256_B;
    }

    private static BigInteger rhs(KeyType c, BigInteger x) {
        BigInteger p = p(c);
        return x.pow(3).add(a(c).multiply(x)).add(b(c)).mod(p);
    }

    public static byte[] compress(KeyType curve, BigInteger x, BigInteger y) {
        BigInteger p = p(curve);
        if (x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0
                || !y.multiply(y).mod(p).equals(rhs(curve, x))) {
            throw new MultikeyException("Point is not on the curve " + curve);
        }
        byte[] out = new byte[33];
        out[0] = (byte) (y.testBit(0) ? 3 : 2);
        byte[] xb = x.toByteArray();
        int len = Math.min(xb.length, 32);
        System.arraycopy(xb, xb.length - len, out, 33 - len, len);
        return out;
    }

    /** Returns {x, y}. */
    public static BigInteger[] decompress(KeyType curve, byte[] compressed33) {
        BigInteger p = p(curve);
        if (compressed33.length != 33 || (compressed33[0] != 2 && compressed33[0] != 3)) {
            throw new MultikeyException("Not a 33-byte compressed point");
        }
        byte[] xb = new byte[32];
        System.arraycopy(compressed33, 1, xb, 0, 32);
        BigInteger x = new BigInteger(1, xb);
        if (x.compareTo(p) >= 0) {
            throw new MultikeyException("x out of range");
        }
        BigInteger rhs = rhs(curve, x);
        BigInteger y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p); // p = 3 mod 4
        if (!y.multiply(y).mod(p).equals(rhs)) {
            throw new MultikeyException("Point is not on the curve " + curve);
        }
        if (y.testBit(0) != (compressed33[0] == 3)) {
            y = p.subtract(y);
        }
        return new BigInteger[] {x, y};
    }
}
