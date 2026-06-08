package ru.yandex.practicum.oauth0.auth.web;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import ru.yandex.practicum.oauth0.auth.dto.ErrorResponse;
import ru.yandex.practicum.oauth0.auth.exception.OAuthException;

/** Translates auth-server exceptions into OAuth-style error responses with the right status. */
@Slf4j
@RestControllerAdvice
public class AuthExceptionHandler {

    @ExceptionHandler(OAuthException.class)
    public ResponseEntity<ErrorResponse> handleOAuth(OAuthException e) {
        log.warn("OAuth error {} ({}): {}", e.getStatus().value(), e.getError(), e.getMessage());
        return ResponseEntity.status(e.getStatus()).body(new ErrorResponse(e.getError(), e.getMessage()));
    }

    @ExceptionHandler({
            MethodArgumentNotValidException.class,
            MissingServletRequestParameterException.class,
            HttpMessageNotReadableException.class
    })
    public ResponseEntity<ErrorResponse> handleBadRequest(Exception e) {
        log.warn("Bad request: {}", e.getMessage());
        return ResponseEntity.badRequest().body(new ErrorResponse("invalid_request", e.getMessage()));
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ErrorResponse> handleUnsupportedGrantType(MethodArgumentTypeMismatchException e) {
        log.warn("Unsupported parameter value: {}", e.getMessage());
        return ResponseEntity.badRequest()
                .body(new ErrorResponse("unsupported_grant_type", "unsupported value for '" + e.getName() + "'"));
    }
}
