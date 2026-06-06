package ru.yandex.practicum.oauth0.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;

/** OAuth-style error body ({@code {"error": ..., "error_description": ...}}). */
@Getter
@AllArgsConstructor
public class ErrorResponse {

    private final String error;

    @JsonProperty("error_description")
    private final String errorDescription;
}
