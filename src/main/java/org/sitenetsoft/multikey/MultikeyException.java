package org.sitenetsoft.multikey;

/** Thrown for malformed or unsupported keys and encodings. */
public class MultikeyException extends RuntimeException {
    public MultikeyException(String message) {
        super(message);
    }

    public MultikeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
