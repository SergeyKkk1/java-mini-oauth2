package ru.yandex.practicum.oauth0.common.jwt;

import lombok.Getter;

/**
 * Raised when a JWT cannot be trusted. The resource server maps any {@code JwtException} to 401;
 * the auth server's refresh flow maps it to 400. The {@link Reason} is kept for clearer logging.
 */
@Getter
public class JwtException extends RuntimeException {

    public enum Reason {
        MALFORMED,
        ALG_MISMATCH,
        INVALID_SIGNATURE,
        EXPIRED
    }

    private final Reason reason;

    public JwtException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }
}
