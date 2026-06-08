package ru.yandex.practicum.oauth0.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Scopes granted to confidential clients in the client_credentials grant. The entity model gives
 * clients no roles, so a client's authorities are configured here, e.g.
 */
@Getter
@Setter
@Component
@ConfigurationProperties(prefix = "oauth")
public class ClientScopeProperties {

    private Map<String, String> clientScopes = new HashMap<>();
}
