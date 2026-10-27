package org.sitenetsoft.multikey;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class Base58Test {
    @Test
    void roundTripsVectors() {
        assertEquals("", Base58.encode(new byte[0]));
        assertArrayEquals(new byte[0], Base58.decode(""));
        assertEquals("112", Base58.encode(new byte[] {0, 0, 1}));
        assertArrayEquals(new byte[] {0, 0, 1}, Base58.decode("112"));
        byte[] hello = "Hello World!".getBytes(StandardCharsets.UTF_8);
        assertEquals("2NEpo7TZRRrLZSi2U", Base58.encode(hello));
        assertArrayEquals(hello, Base58.decode("2NEpo7TZRRrLZSi2U"));
    }

    @Test
    void rejectsInvalidCharacter() {
        assertThrows(MultikeyException.class, () -> Base58.decode("0OIl"));
    }
}
