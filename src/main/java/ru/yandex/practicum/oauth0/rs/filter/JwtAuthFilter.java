package ru.yandex.practicum.oauth0.rs.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.yandex.practicum.oauth0.common.OAuthConstants;
import ru.yandex.practicum.oauth0.common.config.AuthProperties;
import ru.yandex.practicum.oauth0.common.jwt.DecodedJwt;
import ru.yandex.practicum.oauth0.common.jwt.JwtCodec;
import ru.yandex.practicum.oauth0.common.jwt.JwtException;
import ru.yandex.practicum.oauth0.common.revocation.RevocationStore;
import ru.yandex.practicum.oauth0.rs.security.ResourcePrincipal;

import java.io.IOException;
import java.util.HashSet;

/**
 * Authenticates {@code /api/**} requests from the {@code Authorization: Bearer}.
 * Any failure short-circuits with 401; on success the
 * {@link ResourcePrincipal} is attached for the controller to perform scope checks (403).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    public static final String PRINCIPAL_ATTRIBUTE = "oauthPrincipal";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtCodec jwtCodec;
    private final AuthProperties authProperties;
    private final RevocationStore revocationStore;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            unauthorized(response, "missing bearer token");
            return;
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();

        DecodedJwt jwt;
        try {
            jwt = jwtCodec.verify(token);
            jwtCodec.checkTemporal(jwt);
        } catch (JwtException e) {
            unauthorized(response, e.getReason().name().toLowerCase());
            return;
        }

        if (revocationStore.isRevoked(jwt.getJti())) {
            unauthorized(response, "token revoked");
            return;
        }

        if (!authProperties.getIssuer().equals(jwt.getIssuer())
                || !jwt.getAudiences().contains(OAuthConstants.ACCESS_AUDIENCE)) {
            unauthorized(response, "issuer/audience mismatch");
            return;
        }

        ResourcePrincipal principal = new ResourcePrincipal(jwt.getSubject(), new HashSet<>(jwt.getScopes()));
        request.setAttribute(PRINCIPAL_ATTRIBUTE, principal);
        chain.doFilter(request, response);
    }

    private void unauthorized(HttpServletResponse response, String reason) throws IOException {
        log.info("401 Unauthorized: {}", reason);
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"invalid_token\",\"error_description\":\"" + reason + "\"}");
    }
}
