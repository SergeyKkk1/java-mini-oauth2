package ru.yandex.practicum.oauth0.auth;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import ru.yandex.practicum.oauth0.AbstractAuthIntegrationTest;
import ru.yandex.practicum.oauth0.common.jwt.DecodedJwt;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings({"rawtypes", "unchecked"})
class TokenGrantIntegrationTest extends AbstractAuthIntegrationTest {

    @Test
    void passwordGrant_validCredentials_returnsAccessAndRefreshTokens() {
        HttpEntity<Map<String, String>> request =
                new HttpEntity<>(Map.of("username", "alice", "password", "password"), jsonHeaders());

        ResponseEntity<Map> response = rest.exchange(
                url("/token?grantType=PASSWORD"), HttpMethod.POST, request, Map.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map body = response.getBody();
        assertThat(body).isNotNull();
        assertThat(body).containsKeys("accessToken", "refreshToken");
        assertThat(body.get("tokenType")).isEqualTo("Bearer");
        assertThat(((Number) body.get("expiresIn")).longValue()).isEqualTo(900L);

        DecodedJwt access = jwtCodec.verify((String) body.get("accessToken"));
        assertThat(access.getType()).isEqualTo("at+jwt");
        assertThat(access.getSubject()).isEqualTo("u-1");
        assertThat(access.getScopes()).containsExactlyInAnyOrder("payments:read", "payments:write");

        DecodedJwt refresh = jwtCodec.verify((String) body.get("refreshToken"));
        assertThat(refresh.getType()).isEqualTo("rt+jwt");
        assertThat(refresh.getString("aud")).isEqualTo("auth-server");
    }

    @Test
    void passwordGrant_readerUser_getsOnlyReadScope() {
        HttpEntity<Map<String, String>> request =
                new HttpEntity<>(Map.of("username", "bob", "password", "password"), jsonHeaders());

        ResponseEntity<Map> response = rest.exchange(
                url("/token?grantType=PASSWORD"), HttpMethod.POST, request, Map.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        DecodedJwt access = jwtCodec.verify((String) response.getBody().get("accessToken"));
        assertThat(access.getScopes()).containsExactly("payments:read");
    }

    @Test
    void passwordGrant_wrongPassword_returns401() {
        HttpEntity<Map<String, String>> request =
                new HttpEntity<>(Map.of("username", "alice", "password", "nope"), jsonHeaders());

        ResponseEntity<Map> response = rest.exchange(
                url("/token?grantType=PASSWORD"), HttpMethod.POST, request, Map.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void passwordGrant_missingBody_returns400() {
        HttpEntity<Void> request = new HttpEntity<>(jsonHeaders());

        ResponseEntity<Map> response = rest.exchange(
                url("/token?grantType=PASSWORD"), HttpMethod.POST, request, Map.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void unknownGrantType_returns400() {
        HttpEntity<Map<String, String>> request =
                new HttpEntity<>(Map.of("username", "alice", "password", "password"), jsonHeaders());

        ResponseEntity<Map> response = rest.exchange(
                url("/token?grantType=MAGIC"), HttpMethod.POST, request, Map.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void clientCredentialsGrant_validCredentials_returnsAccessTokenWithoutRefresh() {
        HttpEntity<Void> request = new HttpEntity<>(basicAuth("payments-service", "secret"));

        ResponseEntity<Map> response = rest.exchange(
                url("/token?grantType=CLIENT_CREDENTIALS"), HttpMethod.POST, request, Map.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map body = response.getBody();
        assertThat(body).containsKey("accessToken");
        assertThat(body).doesNotContainKey("refreshToken");

        DecodedJwt access = jwtCodec.verify((String) body.get("accessToken"));
        assertThat(access.getSubject()).isEqualTo("payments-service");
        assertThat(access.getString("client_id")).isEqualTo("payments-service");
        assertThat(access.getScopes()).containsExactlyInAnyOrder("payments:read", "payments:write");
    }

    @Test
    void clientCredentialsGrant_wrongSecret_returns401() {
        HttpEntity<Void> request = new HttpEntity<>(basicAuth("payments-service", "wrong"));

        ResponseEntity<Map> response = rest.exchange(
                url("/token?grantType=CLIENT_CREDENTIALS"), HttpMethod.POST, request, Map.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void clientCredentialsGrant_missingAuthorizationHeader_returns401() {
        HttpEntity<Void> request = new HttpEntity<>(null);

        ResponseEntity<Map> response = rest.exchange(
                url("/token?grantType=CLIENT_CREDENTIALS"), HttpMethod.POST, request, Map.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
