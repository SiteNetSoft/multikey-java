package org.sitenetsoft.multikey;

import java.io.ByteArrayOutputStream;

/** Unsigned LEB128 varints as used by multicodec. */
public final class Varint {
    private Varint() {
    }

    public static byte[] encode(int value) {
        if (value < 0) {
            throw new MultikeyException("Negative varint");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int v = value;
        while (v >= 0x80) {
            out.write((v & 0x7F) | 0x80);
            v >>>= 7;
        }
        out.write(v);
        return out.toByteArray();
    }

    /** Returns {value, bytesRead}. */
    public static int[] decode(byte[] in) {
        int value = 0;
        for (int i = 0; i < in.length && i < 5; i++) {
            if (i == 4 && (in[i] & 0xF8) != 0) {
                throw new MultikeyException("Varint does not fit in an int");
            }
            value |= (in[i] & 0x7F) << (7 * i);
            if ((in[i] & 0x80) == 0) {
                if (i > 0 && in[i] == 0) {
                    throw new MultikeyException("Non-minimal varint");
                }
                return new int[] {value, i + 1};
            }
        }
        throw new MultikeyException("Truncated or oversized varint");
    }
}
