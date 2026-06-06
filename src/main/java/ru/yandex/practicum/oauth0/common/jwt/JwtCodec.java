package ru.yandex.practicum.oauth0.common.jwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import ru.yandex.practicum.oauth0.common.config.AuthProperties;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Hand-rolled HS256 JWT signing and verification (no JWT library), per the project spec.
 *
 * <p>A token is {@code base64url(header) + "." + base64url(payload) + "." + base64url(signature)}
 * where the signature is {@code HMAC-SHA256(base64url(header) + "." + base64url(payload))}.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtCodec {

    public static final String ALG = "HS256";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();
    private static final TypeReference<LinkedHashMap<String, Object>> CLAIMS_TYPE = new TypeReference<>() {
    };

    private final AuthProperties properties;

    /** Builds a signed compact JWT with the given {@code typ} header value and claim set. */
    public String sign(String type, Map<String, Object> claims) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", ALG);
        header.put("typ", type);
        String signingInput = encodeSegment(header) + "." + encodeSegment(claims);
        String signature = ENCODER.encodeToString(hmac(signingInput));
        return signingInput + "." + signature;
    }

    /**
     * Verifies the token structure, algorithm and signature. Does <b>not</b> check expiry — call
     * {@link #checkTemporal(DecodedJwt)} for that.
     *
     * @throws JwtException if the token is malformed, uses an unexpected algorithm, or the
     *                      signature does not match.
     */
    public DecodedJwt verify(String token) {
        if (token == null) {
            throw new JwtException(JwtException.Reason.MALFORMED, "token is null");
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new JwtException(JwtException.Reason.MALFORMED, "token must have three segments");
        }

        JsonNode header = decodeSegment(parts[0]);
        String alg = header.path("alg").asText(null);
        if (!ALG.equals(alg)) {
            throw new JwtException(JwtException.Reason.ALG_MISMATCH, "unsupported alg: " + alg);
        }

        byte[] expected = hmac(parts[0] + "." + parts[1]);
        byte[] actual;
        try {
            actual = DECODER.decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new JwtException(JwtException.Reason.MALFORMED, "signature is not valid base64url");
        }
        if (!MessageDigest.isEqual(expected, actual)) {
            throw new JwtException(JwtException.Reason.INVALID_SIGNATURE, "signature mismatch");
        }

        Map<String, Object> claims = MAPPER.convertValue(decodeSegment(parts[1]), CLAIMS_TYPE);
        return new DecodedJwt(alg, header.path("typ").asText(null), claims);
    }

    /**
     * Validates that the current time falls within {@code [iat - skew, exp + skew]}.
     *
     * @throws JwtException with reason {@link JwtException.Reason#EXPIRED} otherwise.
     */
    public void checkTemporal(DecodedJwt jwt) {
        Duration skew = properties.getSkew();
        Instant now = Instant.now();
        Instant exp = jwt.getExpiresAt();
        if (exp == null) {
            throw new JwtException(JwtException.Reason.EXPIRED, "missing exp claim");
        }
        if (now.isAfter(exp.plus(skew))) {
            throw new JwtException(JwtException.Reason.EXPIRED, "token has expired");
        }
        Instant iat = jwt.getIssuedAt();
        if (iat != null && now.isBefore(iat.minus(skew))) {
            throw new JwtException(JwtException.Reason.EXPIRED, "token is not valid yet");
        }
    }

    private String encodeSegment(Map<String, Object> map) {
        try {
            return ENCODER.encodeToString(MAPPER.writeValueAsBytes(map));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize JWT segment", e);
        }
    }

    private JsonNode decodeSegment(String segment) {
        try {
            return MAPPER.readTree(DECODER.decode(segment));
        } catch (IllegalArgumentException | IOException e) {
            throw new JwtException(JwtException.Reason.MALFORMED, "segment is not valid base64url JSON");
        }
    }

    private byte[] hmac(String signingInput) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(properties.getSecretKey(), HMAC_ALGORITHM));
            return mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to compute HMAC signature", e);
        }
    }
}
