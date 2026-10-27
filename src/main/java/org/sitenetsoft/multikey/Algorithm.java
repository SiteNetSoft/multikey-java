package org.sitenetsoft.multikey;

/** JWS signature algorithms supported by {@link Signatures}. */
public enum Algorithm {
    ES256("ES256"),
    ES256K("ES256K"),
    EDDSA("EdDSA"),
    RS256("RS256");

    private final String jwsName;

    Algorithm(String jwsName) {
        this.jwsName = jwsName;
    }

    /** The JOSE {@code alg} value. */
    public String jwsName() {
        return jwsName;
    }
}
