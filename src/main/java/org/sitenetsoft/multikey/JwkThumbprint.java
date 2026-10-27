package org.sitenetsoft.multikey;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** RFC 7638 JWK thumbprints. */
public final class JwkThumbprint {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JwkThumbprint() {
    }

    /**
     * SHA-256 thumbprint, base64url without padding. Only the required public members take part (lexical order,
     * no whitespace), so a private JWK or one with optional members yields the same thumbprint.
     */
    public static String sha256(Map<String, Object> publicJwk) {
        String kty = Jwk.str(publicJwk, "kty");
        List<String> members = switch (kty) {
            case "EC" -> List.of("crv", "kty", "x", "y");
            case "OKP" -> List.of("crv", "kty", "x");
            case "RSA" -> List.of("e", "kty", "n");
            default -> throw new MultikeyException("Unsupported JWK kty " + kty);
        };
        Map<String, String> canonical = new LinkedHashMap<>();
        for (String m : members) {
            canonical.put(m, Jwk.str(publicJwk, m));
        }
        try {
            byte[] json = MAPPER.writeValueAsString(canonical).getBytes(StandardCharsets.UTF_8);
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(json);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (JsonProcessingException | NoSuchAlgorithmException e) {
            throw new MultikeyException("Cannot compute JWK thumbprint", e);
        }
    }
}
