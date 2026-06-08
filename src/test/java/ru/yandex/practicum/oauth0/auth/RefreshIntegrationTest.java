package ru.yandex.practicum.oauth0.auth;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import ru.yandex.practicum.oauth0.AbstractAuthIntegrationTest;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings({"rawtypes", "unchecked"})
class RefreshIntegrationTest extends AbstractAuthIntegrationTest {

    private String passwordRefreshToken() {
        HttpEntity<Map<String, String>> request =
                new HttpEntity<>(Map.of("username", "alice", "password", "password"), jsonHeaders());
        ResponseEntity<Map> response = rest.exchange(
                url("/token?grantType=PASSWORD"), HttpMethod.POST, request, Map.class);
        return (String) response.getBody().get("refreshToken");
    }

    private ResponseEntity<Map> refresh(String refreshToken) {
        HttpEntity<Map<String, String>> request =
                new HttpEntity<>(Map.of("refreshToken", refreshToken), jsonHeaders());
        return rest.exchange(url("/token/refresh"), HttpMethod.POST, request, Map.class);
    }

    @Test
    void refresh_validToken_rotatesAndReturnsNewPair() {
        String original = passwordRefreshToken();

        ResponseEntity<Map> response = refresh(original);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map body = response.getBody();
        assertThat(body.get("accessToken")).isNotNull();
        assertThat((String) body.get("refreshToken")).isNotEqualTo(original);
    }

    @Test
    void refresh_replayedRotatedToken_revokesWholeFamily() {
        String original = passwordRefreshToken();
        String rotated = (String) refresh(original).getBody().get("refreshToken");

        ResponseEntity<Map> replay = refresh(original);

        assertThat(replay.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(refresh(rotated).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void refresh_expiredToken_returns400() {
        Instant past = Instant.now().minusSeconds(3600);
        String expired = mintRefreshToken("u-1", null, UUID.randomUUID().toString(), past.minusSeconds(60), past);

        ResponseEntity<Map> response = refresh(expired);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void refresh_malformedToken_returns400() {
        assertThat(refresh("not.a.jwt").getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void refresh_accessTokenInsteadOfRefresh_returns400() {
        Instant now = Instant.now();
        String access = mintAccessToken("u-1", null, List.of("payments:read"), now, now.plusSeconds(900));

        assertThat(refresh(access).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
}
