package ru.yandex.practicum.oauth0.auth.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/** Carries an OAuth error code and the HTTP status the auth server should return. */
@Getter
public class OAuthException extends RuntimeException {

    private final HttpStatus status;
    private final String error;

    public OAuthException(HttpStatus status, String error, String description) {
        super(description);
        this.status = status;
        this.error = error;
    }

    /** Client (clientId/secret) authentication failed → 401. */
    public static OAuthException invalidClient() {
        return new OAuthException(HttpStatus.UNAUTHORIZED, "invalid_client", "client authentication failed");
    }

    /** Wrong username/password → 401 (per spec, even though RFC 6749 would use 400). */
    public static OAuthException invalidUserCredentials() {
        return new OAuthException(HttpStatus.UNAUTHORIZED, "invalid_grant", "bad username or password");
    }

    /** Refresh token problems (expired / replayed / unknown) → 400. */
    public static OAuthException invalidGrant(String description) {
        return new OAuthException(HttpStatus.BAD_REQUEST, "invalid_grant", description);
    }

    /** Malformed request (missing parameters etc.) → 400. */
    public static OAuthException invalidRequest(String description) {
        return new OAuthException(HttpStatus.BAD_REQUEST, "invalid_request", description);
    }
}
