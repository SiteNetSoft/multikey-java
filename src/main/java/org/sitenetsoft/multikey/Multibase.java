package org.sitenetsoft.multikey;

import java.util.Base64;

public final class Multibase {
    private Multibase() {
    }

    public static String encodeBase58btc(byte[] in) {
        return "z" + Base58.encode(in);
    }

    /** Supports 'z' (base58btc) and 'u' (base64url, no padding). */
    public static byte[] decode(String in) {
        if (in == null || in.isEmpty()) {
            throw new MultikeyException("Empty multibase string");
        }
        String body = in.substring(1);
        switch (in.charAt(0)) {
            case 'z':
                return Base58.decode(body);
            case 'u':
                try {
                    return Base64.getUrlDecoder().decode(body);
                } catch (IllegalArgumentException e) {
                    throw new MultikeyException("Invalid base64url multibase", e);
                }
            default:
                throw new MultikeyException("Unsupported multibase prefix '" + in.charAt(0) + "'");
        }
    }
}
