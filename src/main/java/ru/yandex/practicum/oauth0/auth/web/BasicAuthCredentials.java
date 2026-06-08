package ru.yandex.practicum.oauth0.auth.web;

import ru.yandex.practicum.oauth0.auth.exception.OAuthException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Parses an {@code Authorization: Basic base64(clientId:clientSecret)} header. */
public record BasicAuthCredentials(String clientId, String clientSecret) {

    public static BasicAuthCredentials parse(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, "Basic ", 0, 6)) {
            throw OAuthException.invalidClient();
        }
        String decoded;
        try {
            byte[] raw = Base64.getDecoder().decode(authorizationHeader.substring(6).trim());
            decoded = new String(raw, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw OAuthException.invalidClient();
        }
        int separator = decoded.indexOf(':');
        if (separator < 0) {
            throw OAuthException.invalidClient();
        }
        return new BasicAuthCredentials(decoded.substring(0, separator), decoded.substring(separator + 1));
    }
}
