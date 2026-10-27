package org.sitenetsoft.multikey;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwkThumbprintTest {

    @Test
    @SuppressWarnings("unchecked")
    void rfc7638Example() {
        JsonNode v = Vectors.load("rfc7638-example.json");
        Map<String, Object> jwk = new ObjectMapper().convertValue(v.get("jwk"), Map.class);
        assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", JwkThumbprint.sha256(jwk));
        assertEquals(v.get("thumbprint").asText(), JwkThumbprint.sha256(jwk));
    }

    @Test
    void ignoresOptionalAndPrivateMembers() {
        KeyPair kp = KeyPairs.generate(KeyType.P256);
        Map<String, Object> pub = Jwk.of(kp.getPublic());
        Map<String, Object> priv = new HashMap<>(Jwk.ofPrivate(kp.getPrivate(), kp.getPublic()));
        priv.put("kid", "k1");
        priv.put("use", "sig");
        assertEquals(JwkThumbprint.sha256(pub), JwkThumbprint.sha256(priv));
    }

    @Test
    void rejectsMissingRequiredMember() {
        assertThrows(MultikeyException.class, () -> JwkThumbprint.sha256(Map.of("kty", "EC", "crv", "P-256")));
    }
}
