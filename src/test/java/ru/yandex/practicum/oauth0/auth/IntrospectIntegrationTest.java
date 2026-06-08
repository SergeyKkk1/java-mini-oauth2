package ru.yandex.practicum.oauth0.auth;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import ru.yandex.practicum.oauth0.AbstractAuthIntegrationTest;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings({"rawtypes", "unchecked"})
class IntrospectIntegrationTest extends AbstractAuthIntegrationTest {

    private String clientAccessToken() {
        HttpEntity<Void> request = new HttpEntity<>(basicAuth("payments-service", "secret"));
        ResponseEntity<Map> response = rest.exchange(
                url("/token?grantType=CLIENT_CREDENTIALS"), HttpMethod.POST, request, Map.class);
        return (String) response.getBody().get("accessToken");
    }

    private ResponseEntity<Map> introspect(HttpHeaders headers, String token) {
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, String>> request = new HttpEntity<>(Map.of("token", token), headers);
        return rest.exchange(url("/token/introspect"), HttpMethod.POST, request, Map.class);
    }

    @Test
    void introspect_validAccessToken_returnsActiveWithMetadata() {
        String accessToken = clientAccessToken();

        ResponseEntity<Map> response = introspect(basicAuth("payments-service", "secret"), accessToken);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map body = response.getBody();
        assertThat(body.get("active")).isEqualTo(Boolean.TRUE);
        assertThat(body.get("clientId")).isEqualTo("payments-service");
        assertThat(body.get("sub")).isEqualTo("payments-service");
        assertThat(body.get("tokenType")).isEqualTo("Bearer");
        assertThat(body.get("iss")).isEqualTo("mini-oauth2");
        assertThat(body.get("aud")).isEqualTo("payments-api");
        assertThat((String) body.get("scope")).contains("payments:read", "payments:write");
        assertThat(body).containsKeys("exp", "iat", "jti");
    }

    @Test
    void introspect_revokedToken_returnsInactive() {
        String accessToken = clientAccessToken();
        revocationStore.revoke(jwtCodec.verify(accessToken).getJti(), Instant.now().plusSeconds(900));

        ResponseEntity<Map> response = introspect(basicAuth("payments-service", "secret"), accessToken);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().get("active")).isEqualTo(Boolean.FALSE);
        assertThat(response.getBody()).doesNotContainKeys("sub", "scope", "clientId");
    }

    @Test
    void introspect_expiredToken_returnsInactive() {
        Instant past = Instant.now().minusSeconds(3600);
        String expired = mintAccessToken("u-1", null, List.of("payments:read"), past.minusSeconds(60), past);

        ResponseEntity<Map> response = introspect(basicAuth("payments-service", "secret"), expired);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().get("active")).isEqualTo(Boolean.FALSE);
    }

    @Test
    void introspect_garbageToken_returnsActiveFalse() {
        ResponseEntity<Map> response = introspect(basicAuth("payments-service", "secret"), "garbage.token.value");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody().get("active")).isEqualTo(Boolean.FALSE);
    }

    @Test
    void introspect_badClientCredentials_returns401() {
        String accessToken = clientAccessToken();

        ResponseEntity<Map> response = introspect(basicAuth("payments-service", "wrong"), accessToken);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void introspect_missingAuthorization_returns401() {
        String accessToken = clientAccessToken();

        ResponseEntity<Map> response = introspect(new HttpHeaders(), accessToken);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
