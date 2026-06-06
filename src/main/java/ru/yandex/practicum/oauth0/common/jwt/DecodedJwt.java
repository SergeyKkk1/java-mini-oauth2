package ru.yandex.practicum.oauth0.common.jwt;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * A verified JWT: its header algorithm/type plus the decoded claim set, with typed accessors for
 * the claims this project uses.
 */
@Getter
@RequiredArgsConstructor
public class DecodedJwt {

    private final String algorithm;
    private final String type;
    private final Map<String, Object> claims;

    public String getString(String name) {
        Object value = claims.get(name);
        return value == null ? null : String.valueOf(value);
    }

    public Instant getInstant(String name) {
        Object value = claims.get(name);
        return value == null ? null : Instant.ofEpochSecond(((Number) value).longValue());
    }

    public String getIssuer() {
        return getString("iss");
    }

    public String getSubject() {
        return getString("sub");
    }

    public String getJti() {
        return getString("jti");
    }

    public String getClientId() {
        return getString("client_id");
    }

    public String getFamilyId() {
        return getString("family_id");
    }

    public Instant getIssuedAt() {
        return getInstant("iat");
    }

    public Instant getExpiresAt() {
        return getInstant("exp");
    }

    @SuppressWarnings("unchecked")
    public List<String> getAudiences() {
        Object value = claims.get("aud");
        if (value == null) {
            return Collections.emptyList();
        }
        if (value instanceof List) {
            return (List<String>) value;
        }
        return List.of(String.valueOf(value));
    }

    /** The {@code scope} claim split into individual scopes (RFC 9068 space-delimited string). */
    public List<String> getScopes() {
        String scope = getString("scope");
        if (scope == null || scope.isBlank()) {
            return Collections.emptyList();
        }
        return List.of(scope.trim().split("\\s+"));
    }
}
