package ru.yandex.practicum.oauth0.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Body of {@code POST /token/revoke}. */
@Getter
@Setter
@NoArgsConstructor
public class RevokeRequest {

    @NotBlank
    private String token;
}
