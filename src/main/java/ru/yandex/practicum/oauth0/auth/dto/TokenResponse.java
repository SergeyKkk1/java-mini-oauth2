package ru.yandex.practicum.oauth0.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Getter;

/**
 * Token endpoint response. {@code refreshToken} is omitted for the client_credentials grant
 * (services do not get refresh tokens).
 */
@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenResponse {

    private final String accessToken;
    private final String tokenType;
    private final long expiresIn;
    private final String refreshToken;
}
