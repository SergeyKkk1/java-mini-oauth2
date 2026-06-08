package ru.yandex.practicum.oauth0.rs.exception;

import lombok.Getter;

/** Raised when a validated token lacks the scope an endpoint requires → 403. */
@Getter
public class InsufficientScopeException extends RuntimeException {

    private final String requiredScope;

    public InsufficientScopeException(String requiredScope) {
        super("missing required scope: " + requiredScope);
        this.requiredScope = requiredScope;
    }
}
