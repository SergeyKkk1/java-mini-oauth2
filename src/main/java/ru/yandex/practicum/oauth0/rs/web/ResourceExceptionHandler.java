package ru.yandex.practicum.oauth0.rs.web;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import ru.yandex.practicum.oauth0.rs.exception.InsufficientScopeException;

import java.util.Map;

/** Maps resource-server authorization failures to 403 (401 is written directly by the auth filter). */
@Slf4j
@RestControllerAdvice
public class ResourceExceptionHandler {

    @ExceptionHandler(InsufficientScopeException.class)
    public ResponseEntity<Map<String, String>> handleInsufficientScope(InsufficientScopeException e) {
        log.info("403 Forbidden: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "insufficient_scope", "error_description", e.getMessage()));
    }
}
