package ru.yandex.practicum.oauth0.common.revocation;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory revocation store used in the {@code test} profile so the integration tests need no
 * running Redis.
 */
@Slf4j
@Component
@Profile("test")
public class InMemoryRevocationStore implements RevocationStore {

    private final Map<String, Instant> revoked = new ConcurrentHashMap<>();

    @Override
    public void revoke(String jti, Instant expiresAt) {
        revoked.put(jti, expiresAt);
        log.info("Revoked access token jti={} (in-memory)", jti);
    }

    @Override
    public boolean isRevoked(String jti) {
        Instant expiresAt = revoked.get(jti);
        if (expiresAt == null) {
            return false;
        }
        if (Instant.now().isAfter(expiresAt)) {
            revoked.remove(jti);
            return false;
        }
        return true;
    }
}
