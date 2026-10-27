package org.sitenetsoft.multikey;

public enum KeyType {
    ED25519(0xED),
    P256(0x1200),
    SECP256K1(0xE7),
    RSA(0x1205);

    private final int multicodec;

    KeyType(int multicodec) {
        this.multicodec = multicodec;
    }

    public int multicodec() {
        return multicodec;
    }

    public static KeyType fromMulticodec(int code) {
        for (KeyType t : values()) {
            if (t.multicodec == code) {
                return t;
            }
        }
        throw new MultikeyException("Unsupported multicodec 0x" + Integer.toHexString(code));
    }
}
