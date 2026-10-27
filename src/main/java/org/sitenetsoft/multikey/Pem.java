package org.sitenetsoft.multikey;

import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PEM {@code PUBLIC KEY} (X.509 SubjectPublicKeyInfo) and {@code PRIVATE KEY} (unencrypted PKCS#8) blocks for
 * P-256, secp256k1, Ed25519 and RSA keys.
 */
public final class Pem {
    private static final Pattern BLOCK = Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \\1-----", Pattern.DOTALL);
    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] OID_EC = HEX.parseHex("2a8648ce3d0201");
    private static final byte[] OID_P256 = HEX.parseHex("2a8648ce3d030107");
    private static final byte[] OID_K256 = HEX.parseHex("2b8104000a");
    private static final byte[] OID_ED25519 = HEX.parseHex("2b6570");
    private static final byte[] OID_RSA = HEX.parseHex("2a864886f70d010101");

    private Pem() {
    }

    /** Every key block in {@code pem}, in order; text outside blocks is ignored. */
    public static List<Key> parseAll(String pem) {
        List<Key> keys = new ArrayList<>();
        Matcher m = BLOCK.matcher(pem);
        while (m.find()) {
            String label = m.group(1);
            boolean priv = switch (label) {
                case "PUBLIC KEY" -> false;
                case "PRIVATE KEY" -> true;
                default -> throw new MultikeyException("Unsupported PEM block " + label);
            };
            byte[] der;
            try {
                der = Base64.getDecoder().decode(m.group(2).replaceAll("\\s", ""));
            } catch (IllegalArgumentException e) {
                throw new MultikeyException("Invalid base64 in PEM " + label + " block");
            }
            keys.add(priv ? privateKey(der) : publicKey(der));
        }
        return keys;
    }

    /** {@code PUBLIC KEY} for public keys, {@code PRIVATE KEY} (PKCS#8) for private keys; 64-column base64. */
    public static String encode(Key key) {
        String label;
        if (key instanceof PublicKey && "X.509".equals(key.getFormat())) {
            label = "PUBLIC KEY";
        } else if (key instanceof PrivateKey && "PKCS#8".equals(key.getFormat())) {
            label = "PRIVATE KEY";
        } else {
            throw new MultikeyException("Cannot PEM-encode " + key.getAlgorithm() + " key in format "
                    + key.getFormat());
        }
        String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(key.getEncoded());
        return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
    }

    private static PublicKey publicKey(byte[] der) {
        KeyType type = detect(der, false);
        try {
            return switch (type) {
                case P256 -> KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
                case ED25519 -> KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
                case RSA -> KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
                case SECP256K1 -> Bc.secp256k1(ops -> ops.publicKeyFromSpki(der));
            };
        } catch (MultikeyException e) {
            throw e;
        } catch (Exception e) {
            throw new MultikeyException("Invalid " + type + " public key", e);
        }
    }

    private static PrivateKey privateKey(byte[] der) {
        KeyType type = detect(der, true);
        try {
            return switch (type) {
                case P256 -> KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
                case ED25519 -> KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
                case RSA -> KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
                case SECP256K1 -> Bc.secp256k1(ops -> ops.privateKeyFromPkcs8(der));
            };
        } catch (MultikeyException e) {
            throw e;
        } catch (Exception e) {
            // no cause: provider messages may echo key material
            throw new MultikeyException("Invalid " + type + " private key");
        }
    }

    /**
     * Reads the AlgorithmIdentifier of a SubjectPublicKeyInfo ({@code SEQ { SEQ { OID, params }, BIT STRING }})
     * or a PKCS#8 PrivateKeyInfo ({@code SEQ { INTEGER, SEQ { OID, params }, OCTET STRING }}).
     */
    private static KeyType detect(byte[] der, boolean priv) {
        Der d = new Der(der);
        d.enter(0x30);
        if (priv) {
            d.read(0x02);
        }
        d.enter(0x30);
        byte[] oid = d.read(0x06);
        if (Arrays.equals(oid, OID_ED25519)) {
            return KeyType.ED25519;
        }
        if (Arrays.equals(oid, OID_RSA)) {
            return KeyType.RSA;
        }
        if (Arrays.equals(oid, OID_EC)) {
            byte[] curve = d.read(0x06);
            if (Arrays.equals(curve, OID_P256)) {
                return KeyType.P256;
            }
            if (Arrays.equals(curve, OID_K256)) {
                return KeyType.SECP256K1;
            }
            throw new MultikeyException("Unsupported EC curve in PEM key");
        }
        throw new MultikeyException("Unsupported key algorithm in PEM key");
    }

    /** Minimal forward-only DER cursor, enough to reach the AlgorithmIdentifier. */
    private static final class Der {
        private final byte[] b;
        private int pos;

        Der(byte[] b) {
            this.b = b;
        }

        private int header(int tag) {
            if (pos + 2 > b.length || (b[pos] & 0xff) != tag) {
                throw new MultikeyException("Malformed DER in PEM key");
            }
            pos++;
            int len = b[pos++] & 0xff;
            if (len >= 0x80) {
                int n = len & 0x7f;
                if (n == 0 || n > 3 || pos + n > b.length) {
                    throw new MultikeyException("Malformed DER in PEM key");
                }
                len = 0;
                for (int i = 0; i < n; i++) {
                    len = (len << 8) | (b[pos++] & 0xff);
                }
            }
            if (pos + len > b.length) {
                throw new MultikeyException("Malformed DER in PEM key");
            }
            return len;
        }

        void enter(int tag) {
            header(tag);
        }

        byte[] read(int tag) {
            int len = header(tag);
            byte[] out = Arrays.copyOfRange(b, pos, pos + len);
            pos += len;
            return out;
        }
    }
}
