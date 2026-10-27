package org.sitenetsoft.multikey;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MultikeyTest {
    private static String multibase(String did) {
        return did.substring("did:key:".length());
    }

    @Test
    void parsesAtprotoP256() {
        Multikey key = Multikey.parse(multibase(Vectors.p256Did()));
        assertEquals(KeyType.P256, key.type());
        assertEquals(33, key.publicKeyBytes().length);
        assertEquals(multibase(Vectors.p256Did()), key.encode());
    }

    @Test
    void parsesAtprotoK256() {
        Multikey key = Multikey.parse(multibase(Vectors.k256Did()));
        assertEquals(KeyType.SECP256K1, key.type());
        assertEquals(33, key.publicKeyBytes().length);
        assertEquals(multibase(Vectors.k256Did()), key.encode());
    }

    @Test
    void rejectsUnknownCodec() {
        String bogus = Multibase.encodeBase58btc(concat(Varint.encode(0x1234), new byte[33]));
        assertThrows(MultikeyException.class, () -> Multikey.parse(bogus));
    }

    @Test
    void rejectsNonBase58btc() {
        assertThrows(MultikeyException.class, () -> Multikey.parse("f1200abcdef"));
        assertThrows(MultikeyException.class, () -> Multikey.parse(""));
    }

    @Test
    void varintRoundTrips() {
        for (int v : new int[] {0, 1, 127, 128, 0xE7, 0xED, 0x1200, 0x1205, 1 << 20}) {
            byte[] enc = Varint.encode(v);
            assertArrayEquals(new int[] {v, enc.length}, Varint.decode(enc));
        }
        assertArrayEquals(new byte[] {(byte) 0x80, 0x24}, Varint.encode(0x1200));
    }

    @Test
    void varintRejectsMalformed() {
        assertThrows(MultikeyException.class, () -> Varint.decode(new byte[] {(byte) 0xE7, (byte) 0x81, 0x00}));
        assertThrows(MultikeyException.class,
                () -> Varint.decode(new byte[] {(byte) 0xE7, (byte) 0x81, (byte) 0x80, (byte) 0x80, 0x70}));
        assertThrows(MultikeyException.class, () -> Varint.decode(new byte[] {(byte) 0x80}));
        assertThrows(MultikeyException.class, () -> Varint.decode(new byte[0]));
    }

    @Test
    void rejectsOverlongCodecPrefix() {
        byte[] raw = new byte[3 + 33];
        raw[0] = (byte) 0xE7;
        raw[1] = (byte) 0x81;
        raw[2] = 0x00;
        raw[3] = 2;
        assertThrows(MultikeyException.class, () -> Multikey.parse(Multibase.encodeBase58btc(raw)));
    }

    @Test
    void multibaseRejectsPaddedBase64url() {
        assertThrows(MultikeyException.class, () -> Multibase.decode("uAQID-w=="));
    }

    @Test
    void multibaseDecodesBase64url() {
        assertArrayEquals(new byte[] {1, 2, 3, (byte) 0xfb}, Multibase.decode("uAQID-w"));
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}
