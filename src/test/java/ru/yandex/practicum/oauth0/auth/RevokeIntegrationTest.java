package ru.yandex.practicum.oauth0.auth;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import ru.yandex.practicum.oauth0.AbstractAuthIntegrationTest;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings({"rawtypes", "unchecked"})
class RevokeIntegrationTest extends AbstractAuthIntegrationTest {

    private String clientAccessToken() {
        HttpEntity<Void> request = new HttpEntity<>(basicAuth("payments-service", "secret"));
        ResponseEntity<Map> response = rest.exchange(
                url("/token?grantType=CLIENT_CREDENTIALS"), HttpMethod.POST, request, Map.class);
        return (String) response.getBody().get("accessToken");
    }

    private ResponseEntity<Void> revoke(HttpHeaders headers, String token) {
        headers.setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, String>> request = new HttpEntity<>(Map.of("token", token), headers);
        return rest.exchange(url("/token/revoke"), HttpMethod.POST, request, Void.class);
    }

    @Test
    void revoke_validToken_returns200AndMarksRevoked() {
        String accessToken = clientAccessToken();
        String jti = jwtCodec.verify(accessToken).getJti();
        assertThat(revocationStore.isRevoked(jti)).isFalse();

        ResponseEntity<Void> response = revoke(basicAuth("payments-service", "secret"), accessToken);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(revocationStore.isRevoked(jti)).isTrue();
    }

    @Test
    void revoke_invalidToken_stillReturns200() {
        ResponseEntity<Void> response = revoke(basicAuth("payments-service", "secret"), "garbage.token.value");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void revoke_badClientCredentials_returns401() {
        String accessToken = clientAccessToken();

        ResponseEntity<Void> response = revoke(basicAuth("payments-service", "wrong"), accessToken);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void revoke_missingAuthorization_returns401() {
        String accessToken = clientAccessToken();

        ResponseEntity<Void> response = revoke(new HttpHeaders(), accessToken);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
