package ru.yandex.practicum.oauth0.rs.security;

import java.util.Set;

/** The authenticated caller behind a validated access token: its subject and granted scopes. */
public record ResourcePrincipal(String subject, Set<String> scopes) {

    public boolean hasScope(String scope) {
        return scopes.contains(scope);
    }
}
