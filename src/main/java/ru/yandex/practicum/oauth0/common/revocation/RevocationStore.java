package ru.yandex.practicum.oauth0.common.revocation;

import java.time.Instant;

/**
 * Fast lookup of revoked access tokens, shared between the auth server (which writes on
 * {@code /token/revoke}) and the resource server (which reads on every request).
 */
public interface RevocationStore {

    /** Marks the given access-token {@code jti} as revoked until {@code expiresAt}. */
    void revoke(String jti, Instant expiresAt);

    /** @return {@code true} if the access-token {@code jti} is currently revoked. */
    boolean isRevoked(String jti);
}
