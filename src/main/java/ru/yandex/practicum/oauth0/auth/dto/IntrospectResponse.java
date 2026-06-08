package ru.yandex.practicum.oauth0.auth.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IntrospectResponse {

    private final boolean active;
    private final String scope;
    private final String clientId;
    private final String sub;
    private final String tokenType;
    private final Long exp;
    private final Long iat;
    private final String iss;
    private final String aud;
    private final String jti;

    /** A token that does not exist, cannot be verified, has expired, or has been revoked. */
    public static IntrospectResponse inactive() {
        return IntrospectResponse.builder().active(false).build();
    }
}
