package org.sitenetsoft.multikey;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;

final class Vectors {
    private Vectors() {
    }

    static JsonNode load(String name) {
        try (InputStream in = Vectors.class.getResourceAsStream("/vectors/" + name)) {
            return new ObjectMapper().readTree(in);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static String p256Did() {
        return load("atproto-spec-examples.json").get("p256").asText();
    }

    static String k256Did() {
        return load("atproto-spec-examples.json").get("k256").asText();
    }
}
