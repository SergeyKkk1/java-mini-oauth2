package ru.yandex.practicum.oauth0.common.revocation;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

/**
 * Redis-backed revocation store (the default outside tests). Each revoked token is a key that
 * auto-expires when the token itself would have expired, so the store never grows unbounded.
 */
@Slf4j
@Component
@Profile("!test")
@RequiredArgsConstructor
public class RedisRevocationStore implements RevocationStore {

    private static final String PREFIX = "revoked:at:";

    private final StringRedisTemplate redis;

    @Override
    public void revoke(String jti, Instant expiresAt) {
        long ttlSeconds = Math.max(1, Duration.between(Instant.now(), expiresAt).getSeconds());
        redis.opsForValue().set(PREFIX + jti, "1", Duration.ofSeconds(ttlSeconds));
        log.info("Revoked access token jti={} for {}s", jti, ttlSeconds);
    }

    @Override
    public boolean isRevoked(String jti) {
        return Boolean.TRUE.equals(redis.hasKey(PREFIX + jti));
    }
}
