package org.sitenetsoft.multikey;

import java.math.BigInteger;
import java.util.Arrays;

/** Base58 with the bitcoin alphabet. */
public final class Base58 {
    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger BASE = BigInteger.valueOf(58);

    private Base58() {
    }

    public static String encode(byte[] in) {
        int zeros = 0;
        while (zeros < in.length && in[zeros] == 0) {
            zeros++;
        }
        StringBuilder sb = new StringBuilder();
        BigInteger n = new BigInteger(1, in);
        while (n.signum() > 0) {
            BigInteger[] qr = n.divideAndRemainder(BASE);
            sb.append(ALPHABET.charAt(qr[1].intValue()));
            n = qr[0];
        }
        sb.append("1".repeat(zeros));
        return sb.reverse().toString();
    }

    public static byte[] decode(String in) {
        int zeros = 0;
        while (zeros < in.length() && in.charAt(zeros) == '1') {
            zeros++;
        }
        BigInteger n = BigInteger.ZERO;
        for (int i = 0; i < in.length(); i++) {
            int d = ALPHABET.indexOf(in.charAt(i));
            if (d < 0) {
                throw new MultikeyException("Invalid base58 character '" + in.charAt(i) + "'");
            }
            n = n.multiply(BASE).add(BigInteger.valueOf(d));
        }
        byte[] raw = n.toByteArray();
        int start = (raw.length > 1 && raw[0] == 0) || (raw.length == 1 && raw[0] == 0) ? 1 : 0;
        byte[] out = new byte[zeros + raw.length - start];
        System.arraycopy(raw, start, out, zeros, raw.length - start);
        return n.signum() == 0 ? Arrays.copyOf(out, zeros) : out;
    }
}
