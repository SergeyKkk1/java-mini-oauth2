package ru.yandex.practicum.oauth0.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.yandex.practicum.oauth0.auth.dto.IntrospectResponse;
import ru.yandex.practicum.oauth0.auth.dto.TokenResponse;
import ru.yandex.practicum.oauth0.auth.exception.OAuthException;
import ru.yandex.practicum.oauth0.auth.model.Client;
import ru.yandex.practicum.oauth0.auth.model.RefreshToken;
import ru.yandex.practicum.oauth0.auth.model.User;
import ru.yandex.practicum.oauth0.common.OAuthConstants;
import ru.yandex.practicum.oauth0.common.config.AuthProperties;
import ru.yandex.practicum.oauth0.common.jwt.DecodedJwt;
import ru.yandex.practicum.oauth0.common.jwt.JwtCodec;
import ru.yandex.practicum.oauth0.common.jwt.JwtException;
import ru.yandex.practicum.oauth0.common.revocation.RevocationStore;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Manages the three token flows: password / client_credentials grants, refresh and revoke. */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtCodec jwtCodec;
    private final AuthProperties authProperties;
    private final UserService userService;
    private final ClientService clientService;
    private final RefreshTokenService refreshTokenService;
    private final RevocationStore revocationStore;

    @Transactional
    public TokenResponse passwordGrant(String username, String password) {
        User user = userService.authenticate(username, password);
        Set<String> scopes = userService.scopesFor(user);
        String subject = subjectFor(user);
        Instant now = Instant.now();

        String accessToken = issueAccessToken(subject, null, scopes, now);
        String refreshToken = issueRefreshToken(user.getId(), null, UUID.randomUUID().toString(), subject, now);

        log.info("Issued password-grant tokens for user '{}' (sub={}, scopes={})", username, subject, scopes);
        return response(accessToken, refreshToken);
    }

    @Transactional
    public TokenResponse clientCredentialsGrant(String clientId, String clientSecret) {
        Client client = clientService.authenticate(clientId, clientSecret);
        Set<String> scopes = clientService.scopesFor(client.getId());
        Instant now = Instant.now();

        String accessToken = issueAccessToken(client.getId(), client.getId(), scopes, now);

        log.info("Issued client-credentials token for client '{}' (scopes={})", clientId, scopes);
        return response(accessToken, null);
    }

    @Transactional
    public TokenResponse refresh(String refreshToken) {
        DecodedJwt jwt = decodeRefreshToken(refreshToken);
        RefreshToken stored = refreshTokenService.find(jwt.getJti())
                .orElseThrow(() -> OAuthException.invalidGrant("unknown refresh token"));

        if (stored.isRotated()) {
            // Replay of an already-used token
            refreshTokenService.revokeFamily(stored.getFamilyId());
            throw OAuthException.invalidGrant("refresh token already used; family revoked, please re-authenticate");
        }
        if (stored.getExp().isBefore(Instant.now())) {
            throw OAuthException.invalidGrant("refresh token expired, please re-authenticate");
        }

        refreshTokenService.markRotated(stored);

        User user = userService.getById(stored.getUserId());
        Set<String> scopes = userService.scopesFor(user);
        String subject = subjectFor(user);
        Instant now = Instant.now();

        String newAccess = issueAccessToken(subject, stored.getClientId(), scopes, now);
        String newRefresh = issueRefreshToken(user.getId(), stored.getClientId(), stored.getFamilyId(), subject, now);

        log.info("Rotated refresh token for sub={} (family={})", subject, stored.getFamilyId());
        return response(newAccess, newRefresh);
    }

    @Transactional
    public void revoke(String clientId, String clientSecret, String token) {
        clientService.authenticate(clientId, clientSecret); // 401 if client auth fails
        DecodedJwt jwt;
        try {
            jwt = jwtCodec.verify(token);
        } catch (JwtException e) {
            // still return 200 for an invalid/garbage token — nothing to revoke.
            log.info("Revoke called with an unverifiable token; treating as no-op ({})", e.getReason());
            return;
        }
        Instant exp = jwt.getExpiresAt() != null ? jwt.getExpiresAt() : Instant.now();
        revocationStore.revoke(jwt.getJti(), exp);
        log.info("Revoked access token jti={} on behalf of client '{}'", jwt.getJti(), clientId);
    }

    @Transactional(readOnly = true)
    public IntrospectResponse introspect(String clientId, String clientSecret, String token) {
        clientService.authenticate(clientId, clientSecret); // 401 if client auth fails

        DecodedJwt jwt;
        try {
            jwt = jwtCodec.verify(token);
            jwtCodec.checkTemporal(jwt);
        } catch (JwtException e) {
            log.info("Introspect: token is inactive ({})", e.getReason());
            return IntrospectResponse.inactive();
        }

        if (revocationStore.isRevoked(jwt.getJti())) {
            return IntrospectResponse.inactive();
        }
        // Refresh tokens are invalidated by rotation / family revocation in the database,
        // not via the revocation store, so check their stored state too.
        if (OAuthConstants.REFRESH_TOKEN_TYPE.equals(jwt.getType())) {
            boolean usable = refreshTokenService.find(jwt.getJti())
                    .map(stored -> !stored.isRotated())
                    .orElse(false);
            if (!usable) {
                return IntrospectResponse.inactive();
            }
        }

        return IntrospectResponse.builder()
                .active(true)
                .scope(jwt.getScopes().isEmpty() ? null : String.join(" ", jwt.getScopes()))
                .clientId(jwt.getClientId())
                .sub(jwt.getSubject())
                .tokenType("Bearer")
                .exp(jwt.getExpiresAt() != null ? jwt.getExpiresAt().getEpochSecond() : null)
                .iat(jwt.getIssuedAt() != null ? jwt.getIssuedAt().getEpochSecond() : null)
                .iss(jwt.getIssuer())
                .aud(jwt.getAudiences().isEmpty() ? null : String.join(" ", jwt.getAudiences()))
                .jti(jwt.getJti())
                .build();
    }

    private DecodedJwt decodeRefreshToken(String refreshToken) {
        DecodedJwt jwt;
        try {
            jwt = jwtCodec.verify(refreshToken);
            jwtCodec.checkTemporal(jwt);
        } catch (JwtException e) {
            throw OAuthException.invalidGrant("invalid refresh token, please re-authenticate");
        }
        if (!OAuthConstants.REFRESH_TOKEN_TYPE.equals(jwt.getType())) {
            throw OAuthException.invalidGrant("not a refresh token");
        }
        return jwt;
    }

    private String issueAccessToken(String subject, String clientId, Set<String> scopes, Instant now) {
        String jti = UUID.randomUUID().toString();
        Instant exp = now.plus(authProperties.getAccessTtl());
        Map<String, Object> claims = baseClaims(subject, OAuthConstants.ACCESS_AUDIENCE, jti, now, exp);
        if (clientId != null) {
            claims.put("client_id", clientId);
        }
        claims.put("scope", String.join(" ", scopes));
        return jwtCodec.sign(OAuthConstants.ACCESS_TOKEN_TYPE, claims);
    }

    private String issueRefreshToken(Long userId, String clientId, String familyId, String subject, Instant now) {
        String jti = UUID.randomUUID().toString();
        Instant exp = now.plus(authProperties.getRefreshTtl());
        refreshTokenService.create(jti, userId, clientId, familyId, exp);
        Map<String, Object> claims = baseClaims(subject, OAuthConstants.REFRESH_AUDIENCE, jti, now, exp);
        claims.put("family_id", familyId);
        if (clientId != null) {
            claims.put("client_id", clientId);
        }
        return jwtCodec.sign(OAuthConstants.REFRESH_TOKEN_TYPE, claims);
    }

    private Map<String, Object> baseClaims(String subject, String audience, String jti, Instant iat, Instant exp) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", authProperties.getIssuer());
        claims.put("sub", subject);
        claims.put("aud", audience);
        claims.put("iat", iat.getEpochSecond());
        claims.put("exp", exp.getEpochSecond());
        claims.put("jti", jti);
        return claims;
    }

    private String subjectFor(User user) {
        return "u-" + user.getId();
    }

    private TokenResponse response(String accessToken, String refreshToken) {
        return TokenResponse.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(authProperties.getAccessTtl().getSeconds())
                .refreshToken(refreshToken)
                .build();
    }
}
