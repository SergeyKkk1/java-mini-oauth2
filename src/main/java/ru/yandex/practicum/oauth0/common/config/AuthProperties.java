package ru.yandex.practicum.oauth0.common.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.time.Duration;
import java.util.Base64;

/**
 * Loads OAuth configuration from an external JSON file (default {@code config/auth.json}) plus the
 * HMAC signing secret.
 *
 * <p>The secret intentionally never lives in the committed JSON. It is resolved, in order, from:
 * <ol>
 *     <li>the {@code AUTH_SECRET} environment variable (used locally and in Docker),</li>
 *     <li>the {@code oauth.auth-secret} Spring property (used by tests),</li>
 *     <li>the {@code auth_secret} field of the JSON file.</li>
 * </ol>
 * Startup fails fast if none of these is set. The secret is a Base64-encoded 256-bit HMAC key.
 */
@Slf4j
@Getter
@Component
public class AuthProperties {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String configPath;
    private final String secretFromProperty;

    private Duration accessTtl;
    private Duration refreshTtl;
    private Duration skew;
    private String issuer;
    private byte[] secretKey;

    public AuthProperties(@Value("${oauth.config.path:config/auth.json}") String configPath,
                          @Value("${oauth.auth-secret:}") String secretFromProperty) {
        this.configPath = configPath;
        this.secretFromProperty = secretFromProperty;
    }

    @PostConstruct
    void load() {
        JsonNode node = readConfig();
        this.accessTtl = Duration.ofSeconds(node.path("accessttl").asLong(900));
        this.refreshTtl = Duration.ofDays(node.path("refreshttl").asLong(30));
        this.skew = Duration.ofSeconds(node.path("skew").asLong(30));
        this.issuer = node.path("issuer").asText("mini-oauth2");

        String secret = resolveSecret(node.path("auth_secret").asText(""));
        if (StringUtils.isBlank(secret)) {
            throw new IllegalStateException("OAuth signing secret is not configured. Set the AUTH_SECRET "
                    + "environment variable (or the oauth.auth-secret property, or auth_secret in "
                    + configPath + ").");
        }
        try {
            this.secretKey = Base64.getDecoder().decode(secret.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("AUTH_SECRET must be a Base64-encoded key", e);
        }
        log.info("Loaded auth config from '{}' (issuer={}, accessTtl={}, refreshTtl={}, skew={})",
                configPath, issuer, accessTtl, refreshTtl, skew);
    }

    private String resolveSecret(String fromJson) {
        String fromEnv = System.getenv("AUTH_SECRET");
        if (StringUtils.isNotBlank(fromEnv)) {
            return fromEnv;
        }
        if (StringUtils.isNotBlank(secretFromProperty)) {
            return secretFromProperty;
        }
        return fromJson;
    }

    private JsonNode readConfig() {
        try (InputStream in = openConfig()) {
            return MAPPER.readTree(in);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read auth config from " + configPath, e);
        }
    }

    private InputStream openConfig() throws IOException {
        File file = new File(configPath);
        if (file.exists()) {
            return Files.newInputStream(file.toPath());
        }
        InputStream classpath = getClass().getClassLoader().getResourceAsStream(configPath);
        if (classpath != null) {
            return classpath;
        }
        throw new IOException("auth config not found at '" + configPath
                + "' (looked in the working directory and on the classpath)");
    }
}
