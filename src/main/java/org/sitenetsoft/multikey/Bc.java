package org.sitenetsoft.multikey;

/**
 * Guards calls into the BouncyCastle-only {@link Secp256k1} class. This class references no BouncyCastle type and
 * loads {@link Secp256k1} by name, so callers load and run without BouncyCastle until a secp256k1 operation is
 * requested, and native images build without it (the operation then fails at runtime with {@link #MISSING}).
 */
final class Bc {
    static final String MISSING = "secp256k1 needs org.bouncycastle:bcprov-jdk18on on the classpath";

    interface Call<T> {
        T call(Secp256k1Ops ops) throws Exception;
    }

    private static volatile Secp256k1Ops ops;

    private Bc() {
    }

    static <T> T secp256k1(Call<T> call) {
        Secp256k1Ops o = ops();
        try {
            return call.call(o);
        } catch (NoClassDefFoundError e) {
            throw new MultikeyException(MISSING, e);
        } catch (MultikeyException e) {
            throw e;
        } catch (Exception e) {
            throw new MultikeyException("secp256k1 operation failed", e);
        }
    }

    private static Secp256k1Ops ops() {
        Secp256k1Ops o = ops;
        if (o == null) {
            try {
                o = (Secp256k1Ops) Class.forName("org.sitenetsoft.multikey.Secp256k1")
                        .getDeclaredConstructor().newInstance();
            } catch (ClassNotFoundException | NoClassDefFoundError e) {
                throw new MultikeyException(MISSING, e);
            } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
                throw new MultikeyException("secp256k1 support could not be loaded", e);
            }
            ops = o;
        }
        return o;
    }
}
