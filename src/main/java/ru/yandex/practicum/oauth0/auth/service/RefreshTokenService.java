package ru.yandex.practicum.oauth0.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import ru.yandex.practicum.oauth0.auth.model.RefreshToken;
import ru.yandex.practicum.oauth0.auth.repository.RefreshTokenRepository;

import java.time.Instant;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    public RefreshToken create(String jti, Long userId, String clientId, String familyId, Instant exp) {
        log.debug("Creating refresh token jti={} family={}", jti, familyId);
        RefreshToken token = new RefreshToken();
        token.setId(jti);
        token.setUserId(userId);
        token.setClientId(clientId);
        token.setFamilyId(familyId);
        token.setExp(exp);
        token.setRotated(false);
        return refreshTokenRepository.save(token);
    }

    @Transactional(readOnly = true)
    public Optional<RefreshToken> find(String jti) {
        return refreshTokenRepository.findById(jti);
    }

    @Transactional
    public void markRotated(RefreshToken token) {
        log.debug("Marking refresh token jti={} as rotated", token.getId());
        token.setRotated(true);
        refreshTokenRepository.save(token);
    }

    /**
     * Invalidates every refresh token in a family after a replay is detected. Runs in its own
     * transaction (REQUIRES_NEW) so the revocation commits even though the caller then rolls back
     * by throwing an "invalid_grant" error to the client.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeFamily(String familyId) {
        int revoked = refreshTokenRepository.markFamilyRotated(familyId);
        log.warn("Refresh token reuse detected; revoked {} tokens in family {}", revoked, familyId);
    }
}
