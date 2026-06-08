package ru.yandex.practicum.oauth0.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Body of {@code POST /token/refresh}. */
@Getter
@Setter
@NoArgsConstructor
public class RefreshRequest {

    @NotBlank
    private String refreshToken;
}
