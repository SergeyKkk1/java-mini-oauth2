package ru.yandex.practicum.oauth0.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Body of {@code POST /token/introspect}. */
@Getter
@Setter
@NoArgsConstructor
public class IntrospectRequest {

    @NotBlank
    private String token;
}
