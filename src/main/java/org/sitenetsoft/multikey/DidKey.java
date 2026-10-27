package org.sitenetsoft.multikey;

public final class DidKey {
    private static final String PREFIX = "did:key:";

    private DidKey() {
    }

    public static String of(Multikey key) {
        return PREFIX + key.encode();
    }

    public static Multikey parse(String did) {
        if (did == null || !did.startsWith(PREFIX)) {
            throw new MultikeyException("Not a did:key: " + did);
        }
        return Multikey.parse(did.substring(PREFIX.length()));
    }
}
