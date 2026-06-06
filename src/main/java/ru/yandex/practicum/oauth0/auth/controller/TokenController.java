package ru.yandex.practicum.oauth0.auth.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import ru.yandex.practicum.oauth0.auth.dto.GrantType;
import ru.yandex.practicum.oauth0.auth.dto.PasswordTokenRequest;
import ru.yandex.practicum.oauth0.auth.dto.RefreshRequest;
import ru.yandex.practicum.oauth0.auth.dto.RevokeRequest;
import ru.yandex.practicum.oauth0.auth.dto.TokenResponse;
import ru.yandex.practicum.oauth0.auth.exception.OAuthException;
import ru.yandex.practicum.oauth0.auth.service.TokenService;
import ru.yandex.practicum.oauth0.auth.web.BasicAuthCredentials;

@Slf4j
@RestController
@RequestMapping("/token")
@RequiredArgsConstructor
public class TokenController {

    private final TokenService tokenService;

    /**
     * Issues tokens. {@code PASSWORD} grant reads {username, password} from the JSON body;
     * {@code CLIENT_CREDENTIALS} reads client credentials from the {@code Authorization: Basic} header.
     */
    @PostMapping
    public TokenResponse token(@RequestParam("grantType") GrantType grantType,
                               @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
                               @RequestBody(required = false) PasswordTokenRequest body) {
        return switch (grantType) {
            case PASSWORD -> {
                if (body == null || StringUtils.isAnyBlank(body.getUsername(), body.getPassword())) {
                    throw OAuthException.invalidRequest("username and password are required for the password grant");
                }
                yield tokenService.passwordGrant(body.getUsername(), body.getPassword());
            }
            case CLIENT_CREDENTIALS -> {
                BasicAuthCredentials credentials = BasicAuthCredentials.parse(authorization);
                yield tokenService.clientCredentialsGrant(credentials.clientId(), credentials.clientSecret());
            }
        };
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest request) {
        return tokenService.refresh(request.getRefreshToken());
    }

    @PostMapping("/revoke")
    public ResponseEntity<Void> revoke(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
            @Valid @RequestBody RevokeRequest request) {
        BasicAuthCredentials credentials = BasicAuthCredentials.parse(authorization);
        tokenService.revoke(credentials.clientId(), credentials.clientSecret(), request.getToken());
        return ResponseEntity.ok().build();
    }
}
