package ru.yandex.practicum.oauth0.auth;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

/**
 * Authorization server: issues, refreshes and revokes tokens. Scans its own package plus the
 * shared {@code common} package; listens on port 9000 by default (override with SERVER_PORT).
 */
@SpringBootApplication(scanBasePackages = {
        "ru.yandex.practicum.oauth0.auth",
        "ru.yandex.practicum.oauth0.common"
})
public class AuthApp {

    public static void main(String[] args) {
        new SpringApplicationBuilder(AuthApp.class)
                .properties("server.port=9000")
                .run(args);
    }
}
