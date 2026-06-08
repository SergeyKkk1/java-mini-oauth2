package ru.yandex.practicum.oauth0.common;

/** Domain constants shared by the auth and resource services */
public final class OAuthConstants {

    /** {@code typ} header of an access token (RFC 9068). */
    public static final String ACCESS_TOKEN_TYPE = "at+jwt";

    /** {@code typ} header of a refresh token. */
    public static final String REFRESH_TOKEN_TYPE = "rt+jwt";

    /** {@code aud} claim of access tokens — the resource API that consumes them. */
    public static final String ACCESS_AUDIENCE = "payments-api";

    /** {@code aud} claim of refresh tokens — only the auth server consumes them. */
    public static final String REFRESH_AUDIENCE = "auth-server";

    private OAuthConstants() {
    }
}
