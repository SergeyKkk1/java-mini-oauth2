package ru.yandex.practicum.oauth0.auth.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Body of the password grant: {@code {"username": ..., "password": ...}}. */
@Getter
@Setter
@NoArgsConstructor
public class PasswordTokenRequest {

    private String username;
    private String password;
}
