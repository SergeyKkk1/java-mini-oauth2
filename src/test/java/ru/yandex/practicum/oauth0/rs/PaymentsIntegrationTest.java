package ru.yandex.practicum.oauth0.rs;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import ru.yandex.practicum.oauth0.AbstractResourceIntegrationTest;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings({"rawtypes", "unchecked"})
class PaymentsIntegrationTest extends AbstractResourceIntegrationTest {

    private static final Instant NOW = Instant.now();
    private static final Instant SOON = NOW.plusSeconds(900);

    private ResponseEntity<Map> getPayments(HttpHeaders headers) {
        return rest.exchange(url("/api/payments"), HttpMethod.GET, new HttpEntity<>(headers), Map.class);
    }

    private ResponseEntity<Map> postPayment(String token) {
        HttpHeaders headers = bearer(token);
        headers.setContentType(MediaType.APPLICATION_JSON);
        return rest.exchange(url("/api/payments"), HttpMethod.POST,
                new HttpEntity<>(Map.of("amount", 100, "currency", "USD"), headers), Map.class);
    }

    @Test
    void getPayments_withReadScope_returns200() {
        String token = mintAccessToken("u-1", null, List.of("payments:read"), NOW, SOON);

        ResponseEntity<Map> response = getPayments(bearer(token));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsKey("payments");
        assertThat(response.getBody().get("subject")).isEqualTo("u-1");
    }

    @Test
    void postPayment_withWriteScope_returns200() {
        String token = mintAccessToken("u-1", null, List.of("payments:read", "payments:write"), NOW, SOON);

        assertThat(postPayment(token).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void postPayment_withOnlyReadScope_returns403() {
        String token = mintAccessToken("u-1", null, List.of("payments:read"), NOW, SOON);

        assertThat(postPayment(token).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void getPayments_withoutRequiredScope_returns403() {
        String token = mintAccessToken("u-1", null, List.of(), NOW, SOON);

        assertThat(getPayments(bearer(token)).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void getPayments_withoutToken_returns401() {
        assertThat(getPayments(new HttpHeaders()).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void getPayments_withExpiredToken_returns401() {
        Instant past = NOW.minusSeconds(3600);
        String token = mintAccessToken("u-1", null, List.of("payments:read"), past.minusSeconds(60), past);

        assertThat(getPayments(bearer(token)).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void getPayments_withTamperedSignature_returns401() {
        String token = mintAccessToken("u-1", null, List.of("payments:read"), NOW, SOON);
        String tampered = tamperSignature(token);

        assertThat(getPayments(bearer(tampered)).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void getPayments_withWrongAlgorithm_returns401() {
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        String header = enc.encodeToString("{\"alg\":\"none\",\"typ\":\"at+jwt\"}".getBytes(StandardCharsets.UTF_8));
        String payload = enc.encodeToString("{\"sub\":\"u-1\"}".getBytes(StandardCharsets.UTF_8));
        String token = header + "." + payload + ".AAAA";

        assertThat(getPayments(bearer(token)).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void getPayments_withRevokedToken_returns401() {
        String token = mintAccessToken("u-1", null, List.of("payments:read"), NOW, SOON);
        revocationStore.revoke(jwtCodec.verify(token).getJti(), SOON);

        assertThat(getPayments(bearer(token)).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void getPayments_withRefreshTokenAudience_returns401() {
        String refresh = mintRefreshToken("u-1", null, UUID.randomUUID().toString(), NOW, SOON);

        assertThat(getPayments(bearer(refresh)).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private String tamperSignature(String token) {
        String[] parts = token.split("\\.");
        char first = parts[2].charAt(0);
        char replacement = (first == 'A') ? 'B' : 'A';
        return parts[0] + "." + parts[1] + "." + replacement + parts[2].substring(1);
    }
}
