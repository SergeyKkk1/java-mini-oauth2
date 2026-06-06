package ru.yandex.practicum.oauth0;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import ru.yandex.practicum.oauth0.common.OAuthConstants;
import ru.yandex.practicum.oauth0.common.config.AuthProperties;
import ru.yandex.practicum.oauth0.common.jwt.JwtCodec;
import ru.yandex.practicum.oauth0.common.revocation.RevocationStore;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;


public abstract class AbstractIntegrationTest {

    @Autowired
    protected TestRestTemplate rest;
    @Autowired
    protected JwtCodec jwtCodec;
    @Autowired
    protected AuthProperties authProperties;
    @Autowired
    protected RevocationStore revocationStore;
    @LocalServerPort
    protected int port;

    protected String url(String path) {
        return "http://localhost:" + port + path;
    }

    protected HttpHeaders jsonHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    protected HttpHeaders bearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return headers;
    }

    protected HttpHeaders basicAuth(String id, String secret) {
        HttpHeaders headers = new HttpHeaders();
        String credentials = Base64.getEncoder()
                .encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
        headers.set(HttpHeaders.AUTHORIZATION, "Basic " + credentials);
        return headers;
    }

    protected String mintAccessToken(String subject, String clientId, Collection<String> scopes,
                                     Instant iat, Instant exp) {
        Map<String, Object> claims = baseClaims(subject, OAuthConstants.ACCESS_AUDIENCE, iat, exp);
        if (clientId != null) {
            claims.put("client_id", clientId);
        }
        claims.put("scope", String.join(" ", scopes));
        return jwtCodec.sign(OAuthConstants.ACCESS_TOKEN_TYPE, claims);
    }

    protected String mintRefreshToken(String subject, String clientId, String familyId, Instant iat, Instant exp) {
        Map<String, Object> claims = baseClaims(subject, OAuthConstants.REFRESH_AUDIENCE, iat, exp);
        claims.put("family_id", familyId);
        if (clientId != null) {
            claims.put("client_id", clientId);
        }
        return jwtCodec.sign(OAuthConstants.REFRESH_TOKEN_TYPE, claims);
    }

    private Map<String, Object> baseClaims(String subject, String audience, Instant iat, Instant exp) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", authProperties.getIssuer());
        claims.put("sub", subject);
        claims.put("aud", audience);
        claims.put("iat", iat.getEpochSecond());
        claims.put("exp", exp.getEpochSecond());
        claims.put("jti", UUID.randomUUID().toString());
        return claims;
    }
}
