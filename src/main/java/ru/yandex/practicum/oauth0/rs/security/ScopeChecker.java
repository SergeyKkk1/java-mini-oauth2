package ru.yandex.practicum.oauth0.rs.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import ru.yandex.practicum.oauth0.rs.exception.InsufficientScopeException;

/** Enforces that the caller holds a required scope, throwing {@link InsufficientScopeException} (403) otherwise. */
@Slf4j
@Component
public class ScopeChecker {

    public void require(ResourcePrincipal principal, String scope) {
        if (principal == null || !principal.hasScope(scope)) {
            log.info("Denying request: subject={} lacks scope '{}'",
                    principal == null ? "<none>" : principal.subject(), scope);
            throw new InsufficientScopeException(scope);
        }
    }
}
