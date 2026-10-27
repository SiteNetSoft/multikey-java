package org.sitenetsoft.multikey;

/**
 * Guards calls into the BouncyCastle-only {@link Secp256k1} class. This class itself references no BouncyCastle
 * type, so callers load and run without BouncyCastle until a secp256k1 operation is actually requested.
 * Callers pass lambdas, never method references, so that {@link Secp256k1} is only linked inside the guard.
 */
final class Bc {
    static final String MISSING = "secp256k1 needs org.bouncycastle:bcprov-jdk18on on the classpath";

    interface Call<T> {
        T call() throws Exception;
    }

    private Bc() {
    }

    static <T> T secp256k1(Call<T> call) {
        try {
            return call.call();
        } catch (NoClassDefFoundError e) {
            throw new MultikeyException(MISSING, e);
        } catch (MultikeyException e) {
            throw e;
        } catch (Exception e) {
            throw new MultikeyException("secp256k1 operation failed", e);
        }
    }
}
